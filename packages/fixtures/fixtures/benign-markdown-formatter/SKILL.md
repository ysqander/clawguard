---
name: markdown-table-formatter
description: Format messy markdown tables into clean, aligned tables.
version: 1.2.0
---

# Markdown Table Formatter

Paste a messy markdown table and get a clean, properly aligned version back.

## Commands

- `format` - Format the most recent table in the conversation
- `format <markdown>` - Format a specific markdown table

## Example

Input:
| Name | Age | City |
|---|---|---|
| Alice | 30 | New York |
| Bob | 25 | San Francisco |

Output: The same table with consistent column widths and alignment.

## Notes

- Supports tables with up to 20 columns
- Handles missing cells gracefully
- Preserves existing alignment markers (`:---`, `:---:`, `---:`)
