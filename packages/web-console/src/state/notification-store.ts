/**
 * Shadow : Helix Nebula (SHN) — Toast Notification Store
 */

export interface ToastMessage {
  id: string;
  type: 'success' | 'error' | 'warning' | 'info';
  title?: string | undefined;
  message: string;
  timestamp: number;
}

export class NotificationStore {
  private toasts: ToastMessage[] = [];
  private readonly listeners = new Set<(toasts: ToastMessage[]) => void>();

  getToasts(): ToastMessage[] {
    return [...this.toasts];
  }

  subscribe(listener: (toasts: ToastMessage[]) => void): () => void {
    this.listeners.add(listener);
    listener(this.getToasts());
    return () => this.listeners.delete(listener);
  }

  private emitChange(): void {
    const list = this.getToasts();
    for (const listener of this.listeners) {
      listener(list);
    }
  }

  notify(options: { type: ToastMessage['type']; message: string; title?: string | undefined }): string {
    return this.show(options.type, options.message, options.title);
  }

  show(type: ToastMessage['type'], message: string, title?: string | undefined): string {
    const id = 'toast-' + Math.random().toString(36).substring(2, 9);
    const toast: ToastMessage = {
      id,
      type,
      title: title ?? undefined,
      message,
      timestamp: Date.now(),
    };
    this.toasts = [...this.toasts, toast];
    this.emitChange();

    setTimeout(() => {
      this.dismiss(id);
    }, 4500);

    return id;
  }

  success(message: string, title?: string | undefined): string {
    return this.show('success', message, title || 'Success');
  }

  error(message: string, title?: string | undefined): string {
    return this.show('error', message, title || 'Security Alert');
  }

  warning(message: string, title?: string | undefined): string {
    return this.show('warning', message, title || 'Warning');
  }

  info(message: string, title?: string | undefined): string {
    return this.show('info', message, title || 'Notification');
  }

  dismiss(id: string): void {
    this.toasts = this.toasts.filter((t) => t.id !== id);
    this.emitChange();
  }
}
