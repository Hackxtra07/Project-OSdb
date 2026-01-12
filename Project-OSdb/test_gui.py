import tkinter as tk

try:
    root = tk.Tk()
    root.title("Test GUI")
    label = tk.Label(root, text="If you can see this, GUI is working.")
    label.pack(padx=20, pady=20)
    print("Test GUI started. Window should be visible.")
    root.mainloop()
except Exception as e:
    print(f"Failed to start GUI: {e}")
