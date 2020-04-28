# LSTAR Hook Detection

This is a proof of concept implementation following the write-up on my blog:

[https://revers.engineering/patchguard-detection-of-hypervisor-based-instrospection-p2/](https://revers.engineering/patchguard-detection-of-hypervisor-based-instrospection-p2/)

NOTE: This *is* Patchguard compatible. However this is not VBS/Hypergaurd compatible. To force disable VBS, set the following DWORD key to 0:

`HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\DeviceGuard:EnableVirtualizationBasedSecurity`

Alternatively you can set the current BCD entry `hypervisorlaunchtype` to `off`.

## License

Licensed under MIT license.

Copyright 2020 Aidan Khoury (ajkhoury)

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
