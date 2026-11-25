# ADR 0027: Ranked search and a link graph from what Insight already records

Status: Accepted

## Context
Search was a literal, folded substring match (`documents.search_text LIKE '%…%'`), newest first. With hundreds
of reports, the report that is *about* a threat drowns among reports that mention it once. Analysts also pivot by
hand: report to indicator, indicator to other reports, report to technique, actor to its reports. TIP 3.2 (#17)
asks for relevance ranking and a graph, with the same behaviour on SQLite and PostgreSQL, deterministic and
capped output, and the accessibility rules of ADR 0017.

Constraints: one code path for both databases (the test suite runs on both); TLP per reader everywhere (ADR
0013, 0014); nothing inferred (ADR 0025: links are recorded decisions or extracted mentions); no raw HTML in the
workspace and no new front-end dependency without review.

## Decision
1. **Ranking without a full-text index.** A query is folded words in any order, with "quoted phrases" kept
   together, at most 8. Every word must match (`LIKE` on `search_text`, as before). The database counts each
   word's occurrences with `length(search_text) - length(replace(search_text, word, ''))`, which SQLite and
   PostgreSQL compute identically; Python scores the counts with BM25 (k1 1.2, b 0.75; document frequency and
   average length over the reports the caller may search) plus a boost for words in the title. Ties go to the
   newer report. SQLite FTS5 and PostgreSQL `tsvector` were not used: they tokenise and stem differently, so the
   same query would rank differently on the two databases, and both need shadow tables or triggers kept in step.
2. **Bounded.** Only the newest 5,000 matching reports are ranked (`capped` says when more matched). Results
   page like the inbox (at most 200).
3. **`GET /api/search`** returns ranked results with the matched words, the words found in the title, a score
   and a snippet around the first match. `GET /api/documents?q=` keeps its literal substring meaning, so
   existing scripts and the IOC export's report filter are unchanged. The workspace inbox ranks whenever a query
   is typed and keeps newest-first without one.
4. **A graph of recorded links only.** `GET /api/graph?node=…&depth=1|2` returns nodes (reports, indicators and
   CVEs, ATT&CK techniques, ATT&CK groups, the analyst's actors and campaigns) and edges: a report *mentions*
   an indicator (rejected mentions excluded), a report is *tagged* with a technique, and an analyst *linked* an
   actor, group or campaign to a report, indicator or technique. A report-based edge needs a current report the
   caller may read; every analyst link, actor and campaign is checked against its own TLP label. A node the
   caller may not see is indistinguishable from a missing one (`404`).
5. **Capped and deterministic.** At most 25 neighbours per node (the node is marked `truncated`) and 150 nodes
   (`capped`); neighbours, nodes and edges come in a fixed order, so the same question gives the same graph.
6. **A link map in the workspace.** "Show links" in the reader and on each indicator opens a dialog listing the
   centre item, its direct links and, on request, the items two steps away, grouped by type, with the kind of
   link and what a second-step item is reached through. Every entry is a button that moves it to the centre;
   reports open in the reader. It is plain text and buttons, so keyboard, screen-reader, contrast and
   larger-text rules hold without a drawing library.

## Consequences
- The report about a threat now comes before reports that mention it in passing, on either database, and the
  ranking can be tested exactly.
- Ranking scans the matching reports' text for each query: fine at pilot scale (thousands of reports), not for
  millions. A native full-text index behind the same service remains possible if that changes.
- No stemming or synonyms: `phish` does not find `phishing` unless it is a substring of it, as before.
- Analysts can pivot across reports, indicators, techniques and their own actor and campaign links in a few
  keystrokes, without seeing anything above their TLP limit.
- There is no drawn picture of the graph yet; the API returns nodes and edges, so one can be added once a
  reviewed, accessible component is chosen.
