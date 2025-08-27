"""ml_security.py

Simple, educational ML-security demos:
- Train a tiny classifier on synthetic data (scikit-learn)
- Show accuracy and confusion matrix
- Demonstrate a simple adversarial-noise effect on a sample

All demos run locally and intentionally avoid any external data collection.
"""
from __future__ import annotations
import threading
import numpy as np
import customtkinter as ctk
from tkinter import ttk

try:
    from sklearn.datasets import make_classification
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score, confusion_matrix
    SKLEARN_AVAILABLE = True
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

        self.header = ctk.CTkLabel(self.scrollable_frame, text="ML Security", font=("Arial", 24, "bold"))
        self.header.pack(pady=(18, 8))

        self.desc = ctk.CTkLabel(self.scrollable_frame, text="Train a tiny model and see how small input noise can change predictions.")
        self.desc.pack(pady=(0, 12))

        control_frame = ctk.CTkFrame(self.scrollable_frame)
        control_frame.pack(padx=20, pady=(0, 10), fill="x")

        self.train_btn = ctk.CTkButton(control_frame, text="Train Model", command=self.start_train)
        self.train_btn.grid(row=0, column=0, padx=6, pady=6)

        self.eval_btn = ctk.CTkButton(control_frame, text="Eval on Test", command=self.eval_model)
        self.eval_btn.grid(row=0, column=1, padx=6, pady=6)

        self.adv_btn = ctk.CTkButton(control_frame, text="Adversarial Noise Demo", command=self.adv_demo)
        self.adv_btn.grid(row=0, column=2, padx=6, pady=6)

        self.output_box = ctk.CTkTextbox(self.scrollable_frame, width=740, height=360, font=("Consolas", 12))
        self.output_box.pack(padx=20, pady=(8, 12))
        self.output_box.configure(state="disabled")

        if not SKLEARN_AVAILABLE:
            self.train_btn.configure(state="disabled")
            self.eval_btn.configure(state="disabled")
            self.adv_btn.configure(state="disabled")
            self.append_output("scikit-learn not installed. Add scikit-learn to requirements to enable ML demos.")

        self.model = None
        self.X_test = None
        self.y_test = None

    def append_output(self, text: str):
        self.output_box.configure(state="normal")
        self.output_box.insert(ctk.END, text + "\n")
        self.output_box.see(ctk.END)
        self.output_box.configure(state="disabled")

    def start_train(self):
        if not SKLEARN_AVAILABLE:
            return
        self.append_output("Training model on synthetic data...")

        def _work():
            X, y = make_classification(n_samples=1000, n_features=20, n_informative=5, n_classes=2, random_state=42)
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
            clf = LogisticRegression(max_iter=200)
            clf.fit(X_train, y_train)
            self.model = clf
            self.X_test = X_test
            self.y_test = y_test
            self.append_output("Training complete. Use 'Eval on Test' to view accuracy.")

        threading.Thread(target=_work, daemon=True).start()

    def eval_model(self):
        if not SKLEARN_AVAILABLE or self.model is None:
            self.append_output("Model not trained yet.")
            return
        y_pred = self.model.predict(self.X_test)
        acc = accuracy_score(self.y_test, y_pred)
        cm = confusion_matrix(self.y_test, y_pred)
        self.append_output(f"Test accuracy: {acc:.4f}")
        self.append_output("Confusion matrix:")
        self.append_output(str(cm))

    def adv_demo(self):
        if not SKLEARN_AVAILABLE or self.model is None:
            self.append_output("Model not trained yet.")
            return
        # pick a sample from test set
        idx = 0
        x0 = self.X_test[idx:idx+1]
        orig_pred = self.model.predict(x0)[0]
        self.append_output(f"Original prediction for sample {idx}: {orig_pred}")
        # add small noise
        noise = np.random.normal(scale=0.5, size=x0.shape)
        x_adv = x0 + noise
        adv_pred = self.model.predict(x_adv)[0]
        self.append_output(f"After adding small gaussian noise (scale=0.5), new prediction: {adv_pred}")
        if orig_pred != adv_pred:
            self.append_output("Prediction changed — this demonstrates how fragile models can be to input perturbations.")
        else:
            self.append_output("Prediction unchanged for this noise sample. Try training a weaker model or larger noise.")


def run(on_close=None):
    app = MLSecurityGUI()
    if on_close:
        def handle_close():
            app.destroy()
            on_close()
        app.protocol("WM_DELETE_WINDOW", handle_close)
    app.mainloop()

