using System;
using System.Runtime.InteropServices;
using System.Threading;
using System.Windows.Forms;

namespace AntiSniff
{
    class AutoClosingMessageBox
    {
        private System.Threading.Timer _timeoutTimer;

        private string _caption;

        private AutoClosingMessageBox(string text, string caption, MessageBoxButtons messagebutton, MessageBoxIcon messageicon, int timeout)
        {
            this._caption = caption;
            this._timeoutTimer = new System.Threading.Timer(new TimerCallback(this.OnTimerElapsed), null, timeout, -1);
            using (this._timeoutTimer)
            {
                MessageBox.Show(text, caption, messagebutton, messageicon);
            }
        }

        public static void Show(string text, string caption, MessageBoxButtons messagebutton, MessageBoxIcon messageicon, int timeout)
        {
            new AutoClosingMessageBox(text, caption, messagebutton, messageicon, timeout);
        }

        private void OnTimerElapsed(object state)
        {
            IntPtr intPtr = AutoClosingMessageBox.FindWindow("#32770", this._caption);
            bool flag = intPtr != IntPtr.Zero;
            if (flag)
            {
                AutoClosingMessageBox.SendMessage(intPtr, 16U, IntPtr.Zero, IntPtr.Zero);
            }
            this._timeoutTimer.Dispose();
        }

        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr FindWindow(string lpClassName, string lpWindowName);

        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        private static extern IntPtr SendMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);
    }
}
