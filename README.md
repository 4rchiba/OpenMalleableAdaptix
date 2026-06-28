# Open Malleable Extenders for Adaptix C2

This repository contains a pair of extenders (Agent and Listener) for the Adaptix C2 Framework. They implement Cobalt Strike's Malleable HTTP spec and DLL initialization routine (basically its compatible with most CobaltStrike UDRLs, Crystal Palace stuff etc, you're welcome)

Agent functionality is identical to the default Adaptix C beacon. This repo is just a PoC of the Malleable spec support.

## Function Resolving
Adaptix default C beacon resolves WinAPIs dynamically via function hashes. If you want to use IAT or GetProcAddress based hooks, select the "GetProcAddress" or "Standard Import" function resolution settings during agent generation.

## Operational Issues
**DON'T USE THIS AS IS IN LIVE ENGAGEMENTS!!**
- No OPSEC was added to the default Adaptix C beacon - good news, it supports UDRLs! Add it yourself.
- Adaptix default beacon uses poor encryption standards in transit (hardcoded key). You should probably implement secure E2EE before using it commercially lol.


---

## Build Requirements

### 1. Toolchain & Dependencies
To build the plugins and compile the agent, you need:
* **Go Compiler**: Go version (use the same version as your AdaptixServer)
* **Cross Compiler**: `x86_64-w64-mingw32-g++` and `i686-w64-mingw32-g++` (MinGW-w64).
or just use the docker lol


---

## How to Build

1. **Build the Builder Container**:
   ```bash
   docker build -t open-malleable-builder .
   ```

2. **Run Compilation**:
   Mount the source code directory into the builder container and call `make`:
   ```bash
   docker run --rm -v "$(pwd)":/build open-malleable-builder make
   ```


## Installation & Deployment

To deploy the compiled extenders into your Adaptix C2 Server setup:

1. **Import extenders**:
   Ensure `dist/` outputs are copied into the `server-dist/extenders` directory of your C2 server path:
   ```bash
   mkdir -p /path/to/AdaptixServer/server-dist/extenders/open_malleable_listener
   mkdir -p /path/to/AdaptixServer/server-dist/extenders/open_malleable_agent

   # Copy Listener Plugin
   cp -r open_malleable_listener/dist/* /path/to/AdaptixServer/server-dist/extenders/open_malleable_listener/

   # Copy Agent Plugin
   cp -r open_malleable_agent/dist/* /path/to/AdaptixServer/server-dist/extenders/open_malleable_agent/
   ```

2. **Reload/Restart Adaptix Server**:
   Restart the `AdaptixServer` service (or restart the docker runtime container if running containerized):
3. **Verify In GUI**:
   Check that the "OpenMalleable" protocol is available in the Adaptix listener creation dialog.


# Credits
- [Raising beacons without UDRLs and teaching them how to sleep](https://naksyn.com/cobalt%20strike/2024/07/02/raising-beacons-without-UDRLs-teaching-how-to-sleep.html) - Cobalt Strike Beacon init routine
- [Adaptix Framework](https://github.com/Adaptix-Framework/AdaptixC2)
- [Shamelessly plugging my own OpenMalleableC2 project that I used for this](https://github.com/CodeXTF2/OpenMalleableC2)
- An assortment of clankers

## Obligatory Disclaimer
something something educational purposes something something please dont start a nuclear war with this piece of poorly written (mostly AI slop) code. Thx.