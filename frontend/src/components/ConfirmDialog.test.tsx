import { useState } from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { ConfirmDialog } from './ConfirmDialog';

function DialogHarness() {
  const [isOpen, setIsOpen] = useState(false);

  return (
    <div>
      <button onClick={() => setIsOpen(true)}>Open dialog</button>
      <ConfirmDialog
        isOpen={isOpen}
        title="Delete workspace"
        message="This cannot be undone."
        onConfirm={() => setIsOpen(false)}
        onCancel={() => setIsOpen(false)}
      />
    </div>
  );
}

describe('ConfirmDialog', () => {
  it('renders nothing while closed', () => {
    const { container } = render(
      <ConfirmDialog
        isOpen={false}
        title="Delete workspace"
        message="This cannot be undone."
        onConfirm={vi.fn()}
        onCancel={vi.fn()}
      />,
    );

    expect(container).toBeEmptyDOMElement();
  });

  it('exposes an accessible dialog and focuses Cancel first', async () => {
    render(
      <ConfirmDialog
        isOpen
        title="Delete workspace"
        message="This cannot be undone."
        onConfirm={vi.fn()}
        onCancel={vi.fn()}
      />,
    );

    const dialog = screen.getByRole('alertdialog', { name: 'Delete workspace' });
    expect(dialog).toHaveAccessibleDescription('This cannot be undone.');
    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'Cancel' })).toHaveFocus(),
    );
  });

  it('calls the confirm and cancel handlers', async () => {
    const user = userEvent.setup();
    const onConfirm = vi.fn();
    const onCancel = vi.fn();

    render(
      <ConfirmDialog
        isOpen
        title="Delete workspace"
        message="This cannot be undone."
        onConfirm={onConfirm}
        onCancel={onCancel}
      />,
    );

    await user.click(screen.getByRole('button', { name: 'Confirm & Proceed' }));
    expect(onConfirm).toHaveBeenCalledTimes(1);

    await user.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(onCancel).toHaveBeenCalledTimes(1);
  });

  it('cancels on Escape and backdrop click but not on content click', async () => {
    const user = userEvent.setup();
    const onCancel = vi.fn();
    const { container } = render(
      <ConfirmDialog
        isOpen
        title="Delete workspace"
        message="This cannot be undone."
        onConfirm={vi.fn()}
        onCancel={onCancel}
      />,
    );

    await user.keyboard('{Escape}');
    expect(onCancel).toHaveBeenCalledTimes(1);

    const backdrop = container.querySelector('.wb-modal-backdrop');
    expect(backdrop).not.toBeNull();
    await user.click(backdrop as HTMLElement);
    expect(onCancel).toHaveBeenCalledTimes(2);

    await user.click(screen.getByText('This cannot be undone.'));
    expect(onCancel).toHaveBeenCalledTimes(2);
  });

  it('keeps keyboard focus inside the dialog', async () => {
    const user = userEvent.setup();

    render(
      <ConfirmDialog
        isOpen
        title="Delete workspace"
        message="This cannot be undone."
        onConfirm={vi.fn()}
        onCancel={vi.fn()}
      />,
    );

    const cancel = screen.getByRole('button', { name: 'Cancel' });
    await waitFor(() => expect(cancel).toHaveFocus());

    const close = screen.getByRole('button', { name: 'Close dialog' });
    const confirm = screen.getByRole('button', { name: 'Confirm & Proceed' });

    confirm.focus();
    await user.tab();
    expect(close).toHaveFocus();

    close.focus();
    await user.tab({ shift: true });
    expect(confirm).toHaveFocus();
  });

  it('restores focus to the trigger after closing', async () => {
    const user = userEvent.setup();
    render(<DialogHarness />);

    const trigger = screen.getByRole('button', { name: 'Open dialog' });
    await user.click(trigger);

    const cancel = screen.getByRole('button', { name: 'Cancel' });
    await waitFor(() => expect(cancel).toHaveFocus());

    await user.click(cancel);

    await waitFor(() => expect(trigger).toHaveFocus());
  });
});
