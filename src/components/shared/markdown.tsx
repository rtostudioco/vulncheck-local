'use client'

// SENTINEL DESK 1.0 — Shared markdown renderer (AI output, dark-styled)

import ReactMarkdown from 'react-markdown'

export function Markdown({ content }: { content: string }) {
  return (
    <div className="space-y-2 text-[13px] leading-relaxed [&_blockquote]:border-l-2 [&_blockquote]:border-primary/40 [&_blockquote]:pl-3 [&_blockquote]:text-muted-foreground [&_code]:rounded [&_code]:bg-muted [&_code]:px-1 [&_code]:font-mono [&_code]:text-[11.5px] [&_h2]:mt-3 [&_h2]:border-b [&_h2]:border-border/60 [&_h2]:pb-1 [&_h2]:text-[13px] [&_h2]:font-semibold [&_h3]:text-xs [&_h3]:font-semibold [&_li]:ml-4 [&_li]:list-disc [&_ol_li]:list-decimal [&_p]:text-muted-foreground [&_strong]:text-foreground [&_ul]:space-y-1">
      <ReactMarkdown>{content}</ReactMarkdown>
    </div>
  )
}
