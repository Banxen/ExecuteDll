Executes 32bit dll files. Exports are handled automatically. Prints basic information and exception related information while executing.

As per observation the Cobaltrike beacon dll's DllMain routine address is available in eax register after the ReflectiveLoader export returns. I have used the same thing in my code for transferring code control flow.
