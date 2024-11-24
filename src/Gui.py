import tkinter as tk
from tkinter import ttk
import sv_ttk
from Ruijie import Ruijie

# Set high DPI awareness
try:
    from ctypes import windll

    windll.shcore.SetProcessDpiAwareness(1)
except:
    pass

ruijie = Ruijie()


class LoginInterface(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.remember_var = None
        self.remember_check = None
        self.dropdown_var = None
        self.dropdown_menu = None
        self.password_entry = None
        self.username_entry = None
        self.add_widgets()

    def on_login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        remember = self.remember_check.instate(["selected"])
        carrier = self.dropdown_menu.get()
        print(username, password, remember, carrier)

    def add_widgets(self):
        # 用户名输入框
        ttk.Label(self, text="用户名:").pack(pady=5, anchor="w", padx=20)
        self.username_entry = ttk.Entry(self)
        self.username_entry.pack(pady=5, padx=20, fill="x")
        # 密码输入框
        ttk.Label(self, text="密码:").pack(pady=5, anchor="w", padx=20)
        self.password_entry = ttk.Entry(self, show="*")
        self.password_entry.pack(pady=5, padx=20, fill="x")
        # 复选框和下拉选择框的容器
        options_frame = ttk.Frame(self)
        options_frame.pack(pady=10, padx=20, fill="x")
        # 记住密码复选框
        self.remember_var = tk.BooleanVar(value=True)
        self.remember_check = ttk.Checkbutton(options_frame, text="记住密码", variable=self.remember_var)
        self.remember_check.pack(side="left")
        # 下拉选择框
        self.dropdown_var = tk.StringVar()
        self.dropdown_menu = ttk.Combobox(options_frame, textvariable=self.dropdown_var, width=10, state="readonly")
        self.dropdown_menu["values"] = ["中国电信", "校园网"]
        self.dropdown_menu.pack(side="right", padx=(5, 0))
        ttk.Label(options_frame, text="运营商:").pack(side="right", padx=5)
        # 登录按钮
        login_button = ttk.Button(self, text="登录", command=self.on_login, width=30)
        login_button.pack(pady=20)


class MainInterface(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)

    def add_widgets(self):
        # 退出按钮
        ttk.Button(self, text="退出", command=self.quit).pack(pady=10)


class SettingInterface(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)

    def add_widgets(self):
        # 退出按钮
        pass


class App(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.pack(fill="both", expand=True)
        self.login_interface = LoginInterface(self)
        self.login_interface.pack(fill="both", expand=True)


def timer_function(root):
    status = ''
    if ruijie.detect_env():
        if ruijie.detect_login():
            status = '已登录'
        else:
            status = '未登录'
    else:
        status = '未连接'
    root.title(f'校园网登录程序-{status}')  # 设置窗口标题
    root.after(5000, lambda: timer_function(root))  # 再次设置定时器


def main():
    # 创建主窗口
    root = tk.Tk()
    root.iconbitmap("../img/logo.ico")
    root.title("校园网登录程序")
    root.geometry("450x280")
    # sv_ttk.set_theme("light")
    # 锁定窗口大小
    root.resizable(False, False)

    app = App(root)
    root.after(5000, lambda: timer_function(root))  # 1秒后调用timer_function
    app.mainloop()


if __name__ == '__main__':
    main()
