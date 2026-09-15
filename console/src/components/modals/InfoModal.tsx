import { Button } from '../ui/button'
import {
  Dialog,
  DialogBody,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle
} from '../ui/dialog'
import { usePanels } from '../../store/panels'

export default function InfoModal() {
  const modal = usePanels((state) => state.modal)

  return (
    <Dialog
      open={modal.open}
      onOpenChange={(open) => {
        if (!open) usePanels.getState().closeModal()
      }}
    >
      <DialogContent width={modal.mono ? 760 : 560}>
        <DialogHeader>
          <DialogTitle>{modal.title}</DialogTitle>
          {modal.meta ? <DialogDescription>{modal.meta}</DialogDescription> : null}
        </DialogHeader>

        <DialogBody>
          {modal.loading ? (
            <p className="text-[13px] text-fg-3">读取中…</p>
          ) : modal.mono ? (
            <pre className="overflow-x-auto rounded-sm border border-line bg-raised p-3 font-mono text-[11.5px] leading-relaxed whitespace-pre-wrap text-fg-2">
              {modal.body}
            </pre>
          ) : (
            <p className="max-w-[68ch] text-[13px] leading-relaxed whitespace-pre-wrap text-fg-2">
              {modal.body}
            </p>
          )}

          {modal.links.length ? (
            <ul className="mt-3 border-t border-line pt-3">
              {modal.links.map((link) => (
                <li key={link} className="py-1">
                  <a
                    href={link}
                    target="_blank"
                    rel="noreferrer noopener"
                    className="font-mono text-[11.5px] break-all text-accent underline decoration-accent/40 underline-offset-2 hover:decoration-accent"
                  >
                    {link}
                  </a>
                </li>
              ))}
            </ul>
          ) : null}
        </DialogBody>

        <DialogFooter>
          <DialogClose asChild>
            <Button variant="outline" size="sm">
              关闭
            </Button>
          </DialogClose>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
