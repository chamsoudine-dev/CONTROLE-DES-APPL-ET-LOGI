import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, fireEvent, waitFor } from "@testing-library/react";

afterEach(() => cleanup());

const invoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({ invoke: (...a: unknown[]) => invoke(...a) }));

import { PermissionMatrix } from "./PermissionMatrix";
import { Stepper } from "@/pages/Onboarding";
import { LockScreen } from "@/pages/LockScreen";

describe("PermissionMatrix", () => {
  it("affiche le mode et signale les actions bloquées par la lecture seule", () => {
    render(<PermissionMatrix appId="a" mode="read_only" matrix={{ view: true, redeploy: true }} onChanged={() => undefined} />);
    expect(screen.getByText("Aucune écriture possible chez les fournisseurs.")).toBeTruthy();
    expect(screen.getAllByText("bloqué par le mode").length).toBe(1);
  });

  it("change de mode via le cœur Rust", async () => {
    invoke.mockResolvedValue(undefined);
    const changed = vi.fn();
    render(<PermissionMatrix appId="a" mode="read_only" matrix={{}} onChanged={changed} />);
    fireEvent.click(screen.getByText("Désactivé"));
    await waitFor(() => expect(changed).toHaveBeenCalled());
    expect(invoke).toHaveBeenCalledWith("app_set_mode", { id: "a", mode: "disabled" });
  });
});

describe("Onboarding", () => {
  it("étapes", () => {
    render(<Stepper step={2} />);
    expect(screen.getByText(/GitHub/).textContent).toContain("●");
  });
});

describe("LockScreen", () => {
  it("déverrouille par phrase secrète et affiche l'erreur", async () => {
    invoke.mockRejectedValueOnce({ code: "invalid_passphrase", message: "phrase secrète incorrecte" });
    const onUnlocked = vi.fn();
    const { container } = render(<LockScreen status={{ state: "locked", pin_available: false, secret_backend: "x", autolock_secs: null }} onUnlocked={onUnlocked} />);
    fireEvent.change(container.querySelector("input")!, { target: { value: "mauvaise phrase" } });
    fireEvent.click(screen.getByText("Déverrouiller"));
    await waitFor(() => expect(screen.getByText("phrase secrète incorrecte")).toBeTruthy());
    expect(invoke).toHaveBeenCalledWith("vault_unlock", { passphrase: "mauvaise phrase" });
  });

  it("demande le code 2FA quand nécessaire", () => {
    render(<LockScreen status={{ state: "totp_required", pin_available: false, secret_backend: "x", autolock_secs: null }} onUnlocked={() => undefined} />);
    expect(screen.getByText("Code de double authentification")).toBeTruthy();
  });
});
