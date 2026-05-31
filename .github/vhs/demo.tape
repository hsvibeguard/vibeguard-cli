# Rendered in CI by .github/workflows/make-demo.yml (charmbracelet/vhs-action).
# Produces demo.gif — the README hero. Tweak FontSize/Theme/Sleep and re-run
# the "Make Demo GIF" workflow to regenerate.
Output demo.gif

Set Shell "bash"
Set FontSize 20
Set Width 1200
Set Height 700
Set Theme "Dracula"
Set Padding 24
Set TypingSpeed 55ms

Hide
Type "cd /tmp/vgdemo" Enter
Type "clear" Enter
Show

Type "vibeguard scan . --pack core"
Sleep 800ms
Enter
Sleep 18s
