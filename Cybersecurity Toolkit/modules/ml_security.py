"""ML Security — educational GUI

Provides local-only examples: generate a tiny synthetic dataset, train a simple
classifier, evaluate accuracy, and demonstrate how small additive noise can
change a prediction (adversarial example concept demonstration).

This module does not perform any external network activity and is safe for
local learning. If scikit-learn is not installed, the UI will explain how to
install it and disable training functionality.
"""
from __future__ import annotations
import threading
import time
import sys
import os
import customtkinter as ctk

# Optional dependency: scikit-learn
SKLEARN_AVAILABLE = True
try:
    from sklearn.datasets import make_classification
    from sklearn.model_selection import train_test_split
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import accuracy_score, confusion_matrix
    import numpy as np
except Exception:
    SKLEARN_AVAILABLE = False


class MLSecurityGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("ML Security")
        self.resizable(True, True)
        window_width, window_height = 800, 600
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        x = int((screen_width / 2) - (window_width / 2))
        y = int((screen_height / 2) - (window_height / 2))
        self.geometry(f"{window_width}x{window_height}+{x}+{y}")
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.scrollable_frame = ctk.CTkScrollableFrame(self, width=window_width, height=window_height-20)
        self.scrollable_frame.pack(fill="both", expand=True)

        self.header = ctk.CTkLabel(self.scrollable_frame, text="ML Security", font=("Arial", 28, "bold"))
        self.header.pack(pady=(20, 8))

        if not SKLEARN_AVAILABLE:
            self.notice = ctk.CTkLabel(self.scrollable_frame, text="scikit-learn (and numpy) not found. Install via: pip install scikit-learn numpy", fg_color=None, wraplength=700)
            self.notice.pack(pady=12)

        # Controls
        controls = ctk.CTkFrame(self.scrollable_frame)
        controls.pack(fill="x", padx=20, pady=(6, 12))

        self.samples_label = ctk.CTkLabel(controls, text="Samples:")
        self.samples_label.grid(row=0, column=0, padx=6, pady=6)
        self.samples_entry = ctk.CTkEntry(controls, width=120)
        self.samples_entry.insert(0, "500")
        self.samples_entry.grid(row=0, column=1, padx=6, pady=6)

        self.features_label = ctk.CTkLabel(controls, text="Features:")
        self.features_label.grid(row=0, column=2, padx=6, pady=6)
        self.features_entry = ctk.CTkEntry(controls, width=120)
        self.features_entry.insert(0, "10")
        self.features_entry.grid(row=0, column=3, padx=6, pady=6)

        self.train_btn = ctk.CTkButton(controls, text="Generate & Train", command=self.generate_and_train)
        self.train_btn.grid(row=0, column=4, padx=8, pady=6)

        # Results box
        self.result_box = ctk.CTkTextbox(self.scrollable_frame, width=740, height=200, font=("Consolas", 12))
        self.result_box.pack(padx=20, pady=(6, 12))
        self.result_box.configure(state="disabled")

        # Adversarial demo controls
        adv_frame = ctk.CTkFrame(self.scrollable_frame)
        adv_frame.pack(fill="x", padx=20, pady=(0, 12))
        self.adv_label = ctk.CTkLabel(adv_frame, text="Adversarial noise demo (local sample)")
        self.adv_label.grid(row=0, column=0, padx=6, pady=6)

        self.noise_label = ctk.CTkLabel(adv_frame, text="Noise epsilon:")
        self.noise_label.grid(row=1, column=0, padx=6, pady=6)
        self.noise_entry = ctk.CTkEntry(adv_frame, width=120)
        self.noise_entry.insert(0, "0.1")
        self.noise_entry.grid(row=1, column=1, padx=6, pady=6)

        self.adv_btn = ctk.CTkButton(adv_frame, text="Run Adversarial Demo", command=self.run_adversarial_demo)
        self.adv_btn.grid(row=1, column=2, padx=6, pady=6)

        self._model = None
        self._X_test = None
        self._y_test = None

        if not SKLEARN_AVAILABLE:
            # disable buttons if dependencies missing
            self.train_btn.configure(state="disabled")
            self.adv_btn.configure(state="disabled")

    def append_result(self, text: str):
        def _add():
            self.result_box.configure(state="normal")
            self.result_box.insert(ctk.END, text + "\n")
            self.result_box.see(ctk.END)
            self.result_box.configure(state="disabled")
        try:
            self.after(0, _add)
        except Exception:
            _add()

    def generate_and_train(self):
        if not SKLEARN_AVAILABLE:
            self.append_result("scikit-learn not available.")
            return
        try:
            n_samples = int(self.samples_entry.get())
            n_features = int(self.features_entry.get())
        except Exception:
            self.append_result("Invalid samples/features input")
            return

        self.append_result(f"Generating dataset: samples={n_samples}, features={n_features}...")

        def _work():
            X, y = make_classification(n_samples=n_samples, n_features=n_features, n_informative=max(1, n_features//2), n_redundant=0, random_state=1)
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=1)
            model = LogisticRegression(max_iter=500)
            model.fit(X_train, y_train)
            preds = model.predict(X_test)
            acc = accuracy_score(y_test, preds)
            cm = confusion_matrix(y_test, preds)
            # store for adversarial demo
            self._model = model
            self._X_test = X_test
            self._y_test = y_test
            self.append_result(f"Training complete. Accuracy: {acc:.4f}")
            self.append_result(f"Confusion matrix:\n{cm}")

        threading.Thread(target=_work, daemon=True).start()

    def run_adversarial_demo(self):
        if not SKLEARN_AVAILABLE:
            self.append_result("scikit-learn not available.")
            return
        if self._model is None or self._X_test is None:
            self.append_result("Model not trained yet. Generate & Train first.")
            return
        try:
            eps = float(self.noise_entry.get())
        except Exception:
            self.append_result("Invalid noise epsilon")
            return

        def _work():
            idx = 0
            x = self._X_test[idx:idx+1]
            true = int(self._y_test[idx])
            orig_pred = int(self._model.predict(x)[0])
            # simple additive noise adversarial demo
            noise = np.random.normal(scale=eps, size=x.shape)
            x2 = x + noise
            new_pred = int(self._model.predict(x2)[0])
            self.append_result(f"Sample idx={idx}, true={true}, orig_pred={orig_pred}, new_pred={new_pred}, eps={eps}")
            if orig_pred != new_pred:
                self.append_result("Prediction changed under noise — demonstrates adversarial sensitivity (simple demo).")
            else:
                self.append_result("Prediction unchanged for this sample under the chosen epsilon.")

        threading.Thread(target=_work, daemon=True).start()


def run(on_close=None):
    app = MLSecurityGUI()
    if on_close:
        def handle_close():
            app.destroy()
            on_close()
        app.protocol("WM_DELETE_WINDOW", handle_close)
    app.mainloop()
