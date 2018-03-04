# UTKModule

Ports the PE headers which are used from user API into the kernel code when reading memory from the process in a `LOAD_IMAGE_NOTIFY_ROUTINE` callback to resolve the PE headers with the given base address, points the copy module IAT to the correct one in the virtual process.

Modifies the code of the RtlUserThreadStart callback and reads the arguments passed to it. Then it changes the initial execution argument for the thread to a different location, but with the same executable memory. Bypasses some generic memory integrity checks. 
