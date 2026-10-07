import { render, screen, waitFor } from "@testing-library/react";
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
