# Rendered in CI by .github/workflows/make-demo.yml (charmbracelet/vhs-action).
# Produces demo.gif — the README hero. Tweak FontSize/Theme/Sleep and re-run
# the "Make Demo GIF" workflow to regenerate.
Output demo.gif

Set Shell "bash"
Set FontSize 20
Set Width 1200
Set Height 800
Set Theme "Dracula"
Set Padding 24
Set TypingSpeed 55ms

# Unset CI vars so vibeguard renders its full (non-CI) output, not the quiet one-liner.
Hide
Type "unset CI GITHUB_ACTIONS GITLAB_CI JENKINS_URL CIRCLECI TRAVIS VIBEGUARD_CI" Enter
Type "cd ~/myapp" Enter
Type "clear" Enter
Show

Type "vibeguard scan . --pack core"
Sleep 800ms
Enter
Sleep 20s
