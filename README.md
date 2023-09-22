# DllHookingVeraCrypt
Dll that gets password from a VeraCrypt program. 

Dll that place a hook on WinApi function WideCharToMultiByte. 
Send program to use our fake function that save a password given by user to txt file, then thanks to copying adress of original function we are able to resume a program. 
Thanks to that user would not notice anything.
