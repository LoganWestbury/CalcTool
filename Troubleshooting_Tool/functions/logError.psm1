function pressAnyKey
{
	# Wait for user to press any key to continue, gives user time to read output
	textSeperateLine -inputString "Press any key to continue..."
	$HOST.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | OUT-NULL
	$HOST.UI.RawUI.Flushinputbuffer()
}