# Wireshark (W)MBus plugin
Flonidan has released under GPL this plugin for Wireshark.<br>
This plugin decodes the M-Bus protocol used with Smart Meters.

## Getting started
- Clone Wireshark
- Clone this repository into wireshark/plugins/epan/mbus
- Copy CMakeListsCustom.txt.example to CMakeListsCustom.txt and add plugins/epan/mbus to CUSTOM_PLUGIN_SRC_DIR
- Build as documented here https://www.wireshark.org/docs/wsdg_html_chunked/ChSetupWin32.html

## Out of tree compile MacOSX

Install dependencies 

```bash
brew install wireshark cmake 
```

Build 
```bash
mkdir build
cmake -G Ninja -S . -B build
cmake --build build
```
