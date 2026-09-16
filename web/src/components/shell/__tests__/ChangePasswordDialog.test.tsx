/**
 * WO-H58 — ChangePasswordDialog: self-service password change wired to
 * `POST /api/my/password`. These are render-contract tests (the api module is
 * mocked, not the network). They prove:
 *   - the policy hint + confirm-match gate disable a doomed submit client-side,
 *   - a successful change calls `changeMyPassword(current,new)` then hands off to
 *     `onSignOut` (the token is server-revoked, so the session must end),
 *   - a 400 surfaces the server `detail` VERBATIM (server is source of truth),
 *   - a 429 surfaces a rate-limit note.
 */
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { ApiError, changeMyPassword } = vi.hoisted(() => {
  class ApiError extends Error {
    status: number;
    constructor(status: number, message: string) {
      super(message);
      this.name = "ApiError";
      this.status = status;
    }
  }
  return { ApiError, changeMyPassword: vi.fn() };
});

vi.mock("@/lib/api", () => ({
  ApiError,
  changeMyPassword,
}));

import { ChangePasswordDialog } from "../ChangePasswordDialog";

afterEach(cleanup);
beforeEach(() => {
  changeMyPassword.mockReset();
  vi.useRealTimers();
});

const GOOD_PW = "NewPassw0rd!x9";

function fill(current: string, next: string, confirm: string) {
  fireEvent.change(screen.getByLabelText(/current password/i), {
    target: { value: current },
  });
  fireEvent.change(screen.getByLabelText(/^new password/i), {
    target: { value: next },
  });
  fireEvent.change(screen.getByLabelText(/confirm new password/i), {
    target: { value: confirm },
  });
}

function submitBtn(): HTMLButtonElement {
  return screen.getByRole("button", { name: /change password/i });
}

describe("WO-H58 ChangePasswordDialog", () => {
  it("keeps submit disabled until policy + confirm-match pass", () => {
    render(
      <ChangePasswordDialog open onClose={() => {}} onSignOut={() => {}} />,
    );
    // too-short new password
    fill("old", "short", "short");
    expect(submitBtn().disabled).toBe(true);
    // mismatched confirm
    fill("old", GOOD_PW, "different");
    expect(screen.getByText(/don't match/i)).toBeDefined();
    expect(submitBtn().disabled).toBe(true);
    // all good
    fill("old", GOOD_PW, GOOD_PW);
    expect(submitBtn().disabled).toBe(false);
  });

  it("on success calls changeMyPassword then onSignOut", async () => {
    vi.useFakeTimers();
    changeMyPassword.mockResolvedValue({
      status: "password_changed",
      detail: "Password updated.",
    });
    const onSignOut = vi.fn();
    render(
      <ChangePasswordDialog open onClose={() => {}} onSignOut={onSignOut} />,
    );
    fill("CurrentPw1!aa", GOOD_PW, GOOD_PW);
    await act(async () => {
      fireEvent.click(submitBtn());
    });
    expect(changeMyPassword).toHaveBeenCalledWith("CurrentPw1!aa", GOOD_PW);
    expect(screen.getByText(/sign in again/i)).toBeDefined();
    await act(async () => {
      vi.advanceTimersByTime(1500);
    });
    expect(onSignOut).toHaveBeenCalledTimes(1);
  });

  it("surfaces a 400 server detail verbatim", async () => {
    changeMyPassword.mockRejectedValue(
      new ApiError(400, "Current password is incorrect"),
    );
    render(
      <ChangePasswordDialog open onClose={() => {}} onSignOut={() => {}} />,
    );
    fill("wrong", GOOD_PW, GOOD_PW);
    await act(async () => {
      fireEvent.click(submitBtn());
    });
    await waitFor(() =>
      expect(
        screen.getByText("Current password is incorrect"),
      ).toBeDefined(),
    );
  });

  it("surfaces a friendly rate-limit note on 429", async () => {
    changeMyPassword.mockRejectedValue(new ApiError(429, "Too Many Requests"));
    render(
      <ChangePasswordDialog open onClose={() => {}} onSignOut={() => {}} />,
    );
    fill("CurrentPw1!aa", GOOD_PW, GOOD_PW);
    await act(async () => {
      fireEvent.click(submitBtn());
    });
    await waitFor(() =>
      expect(screen.getByText(/too many attempts/i)).toBeDefined(),
    );
  });
});
