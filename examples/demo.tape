# VibeGuard demo — render with:  vhs examples/demo.tape   (produces demo.gif)
#
# Prereqs (so the recorded scan is fast + clean, not a cold scanner download):
#   pip install vibeguard-cli
#   vibeguard scan .          # run ONCE first to cache scanner binaries
#
Output demo.gif
Set Shell "bash"              # or "pwsh" if you have PowerShell 7
Set FontSize 18
Set Width 1100
Set Height 640
Set Theme "Dracula"
Set Padding 20
Set TypingSpeed 55ms

Hide
Type "clear" Enter
Show

Type "vibeguard scan ."
Sleep 600ms
Enter
Sleep 6s                      # bump to match your warm scan time (usually 3-6s)
