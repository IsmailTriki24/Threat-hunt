import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { LoginForm } from "@/components/login-form";
import { ApiError } from "@/lib/api";

const login = vi.fn();
const replace = vi.fn();
vi.mock("@/lib/auth", () => ({ useAuth: () => ({ login }) }));
vi.mock("next/navigation", () => ({ useRouter: () => ({ replace }) }));

beforeEach(() => { login.mockReset(); replace.mockReset(); });

it("signs in and redirects", async () => {
  login.mockResolvedValue(undefined);
  render(<LoginForm />);
  const user = userEvent.setup();
  await user.type(screen.getByLabelText("Email"), "analyst@acme.example");
  await user.type(screen.getByLabelText("Password"), "pw");
  await user.click(screen.getByRole("button", { name: "Sign in" }));
  await waitFor(() => expect(replace).toHaveBeenCalledWith("/"));
  expect(login).toHaveBeenCalledWith("analyst@acme.example", "pw");
});

it("shows a generic error on bad credentials", async () => {
  login.mockRejectedValue(new ApiError(401, "unauthorized", "Invalid credentials"));
  render(<LoginForm />);
  const user = userEvent.setup();
  await user.type(screen.getByLabelText("Email"), "a@b.co");
  await user.type(screen.getByLabelText("Password"), "x");
  await user.click(screen.getByRole("button", { name: "Sign in" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("Invalid credentials");
  expect(replace).not.toHaveBeenCalled();
});

it("surfaces rate limiting", async () => {
  login.mockRejectedValue(new ApiError(429, "rate_limited", "Too many"));
  render(<LoginForm />);
  const user = userEvent.setup();
  await user.type(screen.getByLabelText("Email"), "a@b.co");
  await user.type(screen.getByLabelText("Password"), "x");
  await user.click(screen.getByRole("button", { name: "Sign in" }));
  expect(await screen.findByRole("alert")).toHaveTextContent(/rate limit/i);
});

it("reveals and hides the password on request", async () => {
  render(<LoginForm />);
  const user = userEvent.setup();
  const field = screen.getByLabelText("Password");
  expect(field).toHaveAttribute("type", "password");
  await user.click(screen.getByRole("button", { name: "Show password" }));
  expect(field).toHaveAttribute("type", "text");
  await user.click(screen.getByRole("button", { name: "Hide password" }));
  expect(field).toHaveAttribute("type", "password");
});

it("warns when Caps Lock is on", async () => {
  render(<LoginForm />);
  const field = screen.getByLabelText("Password");
  field.focus();
  fireEvent.keyDown(field, { key: "a", modifierCapsLock: true });
  expect(await screen.findByRole("status")).toHaveTextContent("Caps Lock is on");
  fireEvent.blur(field);
  expect(screen.queryByRole("status")).not.toBeInTheDocument();
});

it("tells the scene behind it when it is signing in, and when a sign-in is refused", async () => {
  vi.useFakeTimers({ shouldAdvanceTime: true });
  const onStatus = vi.fn();
  login.mockRejectedValue(new ApiError(401, "unauthorized", "Invalid credentials"));
  render(<LoginForm onStatus={onStatus} />);
  const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
  await user.type(screen.getByLabelText("Email"), "a@b.co");
  await user.type(screen.getByLabelText("Password"), "x");
  await user.click(screen.getByRole("button", { name: "Sign in" }));
  await screen.findByRole("alert");
  expect(onStatus.mock.calls.map((c) => c[0])).toEqual(["busy", "denied"]);
  vi.advanceTimersByTime(1500);
  expect(onStatus).toHaveBeenLastCalledWith("idle");
  vi.useRealTimers();
});
