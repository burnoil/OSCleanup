<#
.SYNOPSIS
    GUI wrapper for OSCleanup.ps1 with real-time log monitoring and progress tracking.

.DESCRIPTION
    Enterprise-ready GUI for OS cleanup operations with:
    - Real-time log display with auto-scroll
    - Progress indication and space tracking
    - Parameter selection via checkboxes
    - Admin elevation handling
    - Exit code interpretation
    - BigFix deployment compatible

.NOTES
    Author: MIT Lincoln Laboratory
    Version: 1.0
    Requires: PowerShell 5.1+, .NET Framework 4.5+
#>

#Requires -Version 5.1

# ================================
# EMBEDDED CLEANUP SCRIPT (MODIFIED FOR GUI)
# ================================
$script:CleanupScriptBase64 = 'PCMKLlNZTk9QU0lTCiAgICBDbGVhbnMgdXAgV2luZG93cyBPUyBqdW5rIGFuZCBwZXJmb3JtcyBvcHRpb25hbCBwcmUtZmxpZ2h0IGNoZWNrcwogICAgdG8gaGVscCBwcmV2ZW50IE1TSSAvIENsaWNrLXRvLVJ1biBpbnN0YWxsIGlzc3VlcyAoZS5nLiwgMTYwMykuCgouREVTQ1JJUFRJT04KICAgIC0gTXVzdCBiZSBydW4gYXMgQWRtaW5pc3RyYXRvci4KICAgIC0gUGVyZm9ybXMgc2FmZSBPUyBjbGVhbnVwIG9wZXJhdGlvbnMuCiAgICAtIE9wdGlvbmFsIHByZS1mbGlnaHQgZGV0ZWN0aW9uIGZvcjoKICAgICAgICAqIFBlbmRpbmcgcmVib290CiAgICAgICAgKiBJbnN0YWxsZXIgYnVzeSAobXNpZXhlYykKICAgICAgICAqIE9mZmljZSBDMlIgYnVzeSAocmVhbCBpbnN0YWxscywgbm90IGJhY2tncm91bmQpCiAgICAgICAgKiBJbnN0YWxsZXIgc2VydmljZSByZXN0YXJ0IGZhaWx1cmVzCiAgICAtIFN1cHBvcnRzIHNpbGVudCBvcGVyYXRpb24gdmlhIC1TaWxlbnQKICAgIC0gTG9nZ2luZyB0byAlUHJvZ3JhbURhdGElXE9TQ2xlYW51cAoKLlBBUkFNRVRFUiBBZ2dyZXNzaXZlCiAgICBFbmFibGVzIGFkZGl0aW9uYWwgY2xlYW51cCAoV0VSIHF1ZXVlLCBldGMpLgoKLlBBUkFNRVRFUiBTa2lwUmVjeWNsZUJpbgogICAgU2tpcHMgY2xlYXJpbmcgdGhlIFJlY3ljbGUgQmluLgoKLlBBUkFNRVRFUiBTa2lwUHJlZmxpZ2h0CiAgICBSdW5zIGNsZWFudXAgb25seSBhbmQgYnlwYXNzZXMgYWxsIHByZS1mbGlnaHQgY2hlY2tzLgoKLlBBUkFNRVRFUiBJbnN0YWxsZXJCdXN5TWludXRlcwogICAgSG93IHJlY2VudCBhbiBtc2lleGVjIG11c3QgYmUgKG1pbnV0ZXMpIHRvIGNvdW50IGFzIGJ1c3kuIERlZmF1bHQ6IDEyMC4KCi5QQVJBTUVURVIgV2hhdElmCiAgICBTaG93cyB3aGF0IHdvdWxkIGhhcHBlbiBidXQgbWFrZXMgbm8gY2hhbmdlcy4KCi5QQVJBTUVURVIgU2lsZW50CiAgICBTdXBwcmVzc2VzIGFsbCBjb25zb2xlIG91dHB1dC4gU2NyaXB0IHN0aWxsIHdyaXRlcyBmdWxsIGxvZ3MuCgouRVhJVENPREVTCiAgICAwICBTdWNjZXNzIChvciBwcmVmbGlnaHQgc2tpcHBlZCkKICAgIDEgIEdlbmVyYWwgc2NyaXB0IGVycm9yCiAgICAyMCBQZW5kaW5nIHJlYm9vdAogICAgMjEgSW5zdGFsbGVyIGJ1c3kKICAgIDIyIE9mZmljZSBDMlIgYnVzeQogICAgMjMgSW5zdGFsbGVyIHNlcnZpY2UgcmVzdGFydCBmYWlsdXJlCiM+CgpwYXJhbSgKICAgIFtzd2l0Y2hdJEFnZ3Jlc3NpdmUsCiAgICBbc3dpdGNoXSRTa2lwUmVjeWNsZUJpbiwKICAgIFtzd2l0Y2hdJFNraXBQcmVmbGlnaHQsCiAgICBbaW50XSRJbnN0YWxsZXJCdXN5TWludXRlcyA9IDEyMCwKICAgIFtzd2l0Y2hdJFdoYXRJZiwKICAgIFtzd2l0Y2hdJFNpbGVudAopCgojID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09CiMgTG9nZ2luZyBTZXR1cAojID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09CiRzY3JpcHQ6TG9nUm9vdCA9IEpvaW4tUGF0aCAtUGF0aCAkZW52OlByb2dyYW1EYXRhIC1DaGlsZFBhdGggIk9TQ2xlYW51cCIKaWYgKC1ub3QgKFRlc3QtUGF0aCAkc2NyaXB0OkxvZ1Jvb3QpKSB7CiAgICBOZXctSXRlbSAtUGF0aCAkc2NyaXB0OkxvZ1Jvb3QgLUl0ZW1UeXBlIERpcmVjdG9yeSAtRm9yY2UgfCBPdXQtTnVsbAp9CiR0aW1lc3RhbXAgPSBHZXQtRGF0ZSAtRm9ybWF0ICJ5eXl5TU1kZF9ISG1tc3MiCiRzY3JpcHQ6TG9nRmlsZSA9IEpvaW4tUGF0aCAkc2NyaXB0OkxvZ1Jvb3QgIk9TQ2xlYW51cF8kdGltZXN0YW1wLmxvZyIKCmZ1bmN0aW9uIFdyaXRlLUxvZyB7CiAgICBwYXJhbSgKICAgICAgICBbUGFyYW1ldGVyKE1hbmRhdG9yeSldIFtzdHJpbmddJE1lc3NhZ2UsCiAgICAgICAgW1ZhbGlkYXRlU2V0KCJJTkZPIiwiV0FSTiIsIkVSUk9SIildIFtzdHJpbmddJExldmVsID0gIklORk8iCiAgICApCgogICAgJHRpbWUgPSBHZXQtRGF0ZSAtRm9ybWF0ICJ5eXl5LU1NLWRkIEhIOm1tOnNzIgogICAgJGxpbmUgPSAiWyR0aW1lXSBbJExldmVsXSAkTWVzc2FnZSIKCiAgICAjIFdyaXRlIHRvIEdVSSBpZiBhdmFpbGFibGUgKHVzaW5nIEJlZ2luSW52b2tlIGZvciBub24tYmxvY2tpbmcpCiAgICBpZiAoJHNjcmlwdDpXcml0ZUd1aUxvZykgewogICAgICAgIHRyeSB7CiAgICAgICAgICAgICRwcmVmaXggPSBzd2l0Y2ggKCRMZXZlbCkgewogICAgICAgICAgICAgICAgIldBUk4iICB7ICLimqAgIiB9CiAgICAgICAgICAgICAgICAiRVJST1IiIHsgIuKclyAiIH0KICAgICAgICAgICAgICAgIGRlZmF1bHQgeyAiIiB9CiAgICAgICAgICAgIH0KICAgICAgICAgICAgIyBDYWxsIFdyaXRlR3VpTG9nIGFzeW5jaHJvbm91c2x5IChub24tYmxvY2tpbmcpCiAgICAgICAgICAgICYgJHNjcmlwdDpXcml0ZUd1aUxvZyAiJHByZWZpeCRNZXNzYWdlIgogICAgICAgIH0KICAgICAgICBjYXRjaCB7CiAgICAgICAgICAgICMgR1VJIHVwZGF0ZSBmYWlsZWQsIGZhbGwgYmFjayB0byBjb25zb2xlCiAgICAgICAgICAgIGlmICgtbm90ICRTaWxlbnQpIHsKICAgICAgICAgICAgICAgIFdyaXRlLUhvc3QgJGxpbmUKICAgICAgICAgICAgfQogICAgICAgIH0KICAgIH0KICAgIGVsc2VpZiAoLW5vdCAkU2lsZW50KSB7CiAgICAgICAgV3JpdGUtSG9zdCAkbGluZQogICAgfQoKICAgICMgQWx3YXlzIHdyaXRlIHRvIGxvZyBmaWxlIGZvciByZWNvcmQga2VlcGluZwogICAgQWRkLUNvbnRlbnQgLVBhdGggJHNjcmlwdDpMb2dGaWxlIC1WYWx1ZSAkbGluZQp9CgpXcml0ZS1Mb2cgIj09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0iCldyaXRlLUxvZyAiU3RhcnRpbmcgT1MgUHJlZmxpZ2h0IENsZWFudXAgU2NyaXB0IgpXcml0ZS1Mb2cgIlBhcmFtZXRlcnM6IEFnZ3Jlc3NpdmU9JEFnZ3Jlc3NpdmUgU2tpcFJlY3ljbGVCaW49JFNraXBSZWN5Y2xlQmluIFNraXBQcmVmbGlnaHQ9JFNraXBQcmVmbGlnaHQgSW5zdGFsbGVyQnVzeU1pbnV0ZXM9JEluc3RhbGxlckJ1c3lNaW51dGVzIFdoYXRJZj0kV2hhdElmIFNpbGVudD0kU2lsZW50IgoKIyA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PQojIEFkbWluIENoZWNrCiMgPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0KZnVuY3Rpb24gVGVzdC1Jc0FkbWluIHsKICAgICR3aWQgPSBbU2VjdXJpdHkuUHJpbmNpcGFsLldpbmRvd3NJZGVudGl0eV06OkdldEN1cnJlbnQoKQogICAgJHByaW5jaXBhbCA9IE5ldy1PYmplY3QgU2VjdXJpdHkuUHJpbmNpcGFsLldpbmRvd3NQcmluY2lwYWwoJHdpZCkKICAgIHJldHVybiAkcHJpbmNpcGFsLklzSW5Sb2xlKFtTZWN1cml0eS5QcmluY2lwYWwuV2luZG93c0J1aWx0SW5Sb2xlXTo6QWRtaW5pc3RyYXRvcikKfQoKaWYgKC1ub3QgKFRlc3QtSXNBZG1pbikpIHsKICAgIGlmICgtbm90ICRTaWxlbnQpIHsKICAgICAgICBXcml0ZS1Ib3N0ICJFUlJPUjogU2NyaXB0IG11c3QgYmUgcnVuIGFzIEFkbWluaXN0cmF0b3IuIiAtRm9yZWdyb3VuZENvbG9yIFJlZAogICAgfQogICAgZXhpdCAxCn0KCiMgPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0KIyBIZWxwZXJzCiMgPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0KZnVuY3Rpb24gRm9ybWF0LUJ5dGVzIHsKICAgIHBhcmFtKFtJbnQ2NF0kQnl0ZXMpCiAgICBpZiAoJEJ5dGVzIC1nZSAxR0IpIHsgInswOk4yfSBHQiIgLWYgKCRCeXRlcyAvIDFHQikgfQogICAgZWxzZWlmICgkQnl0ZXMgLWdlIDFNQikgeyAiezA6TjJ9IE1CIiAtZiAoJEJ5dGVzIC8gMU1CKSB9CiAgICBlbHNlaWYgKCRCeXRlcyAtZ2UgMUtCKSB7ICJ7MDpOMn0gS0IiIC1mICgkQnl0ZXMgLyAxS0IpIH0KICAgIGVsc2UgeyAiJEJ5dGVzIEIiIH0KfQoKZnVuY3Rpb24gR2V0LVN5c3RlbURyaXZlRnJlZVNwYWNlIHsKICAgIHRyeSB7CiAgICAgICAgJHJvb3QgPSAkZW52OlN5c3RlbURyaXZlLlRyaW1FbmQoJ1wnKQogICAgICAgICRkcml2ZUxldHRlciA9ICRyb290LlN1YnN0cmluZygwLDEpCiAgICAgICAgJGRyaXZlID0gR2V0LVBTRHJpdmUgLU5hbWUgJGRyaXZlTGV0dGVyIC1FcnJvckFjdGlvbiBTaWxlbnRseUNvbnRpbnVlCgogICAgICAgIGlmICgkZHJpdmUpIHsKICAgICAgICAgICAgcmV0dXJuIFtpbnQ2NF0kZHJpdmUuRnJlZQogICAgICAgIH0KCiAgICAgICAgJGZhbGxiYWNrID0gR2V0LVdtaU9iamVjdCBXaW4zMl9Mb2dpY2FsRGlzayAtRmlsdGVyICJEZXZpY2VJRD0nJHJvb3QnIiAtRXJyb3JBY3Rpb24gU2lsZW50bHlDb250aW51ZQogICAgICAgIGlmICgkZmFsbGJhY2spIHsgcmV0dXJuIFtpbnQ2NF0kZmFsbGJhY2suRnJlZVNwYWNlIH0KICAgIH0KICAgIGNhdGNoIHsKICAgICAgICBXcml0ZS1Mb2cgIkdldC1TeXN0ZW1Ecml2ZUZyZWVTcGFjZSBmYWlsZWQ6ICRfIiAiV0FSTiIKICAgIH0KICAgIHJldHVybiAwCn0KCiRpbml0aWFsRnJlZSA9IEdldC1TeXN0ZW1Ecml2ZUZyZWVTcGFjZQpXcml0ZS1Mb2cgIkluaXRpYWwgZnJlZSBzcGFjZTogJChGb3JtYXQtQnl0ZXMgJGluaXRpYWxGcmVlKSIKCiMgPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0KIyBTYWZlIFJlbW92ZSBXcmFwcGVyCiMgPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0KZnVuY3Rpb24gUmVtb3ZlLUl0ZW1TYWZlIHsKICAgIHBhcmFtKFtQYXJhbWV0ZXIoTWFuZGF0b3J5KV1bc3RyaW5nXSRQYXRoLCBbc3dpdGNoXSRSZWN1cnNlKQoKICAgIGlmICgtbm90IChUZXN0LVBhdGggJFBhdGgpKSB7IFdyaXRlLUxvZyAiUGF0aCBub3QgZm91bmQ6ICRQYXRoIiAiSU5GTyI7IHJldHVybiB9CgogICAgdHJ5IHsKICAgICAgICBpZiAoJFdoYXRJZikgewogICAgICAgICAgICBXcml0ZS1Mb2cgIldoYXRJZjogV291bGQgZGVsZXRlICckUGF0aCciCiAgICAgICAgfSBlbHNlIHsKICAgICAgICAgICAgUmVtb3ZlLUl0ZW0gLUxpdGVyYWxQYXRoICRQYXRoIC1SZWN1cnNlOiRSZWN1cnNlIC1Gb3JjZSAtRXJyb3JBY3Rpb24gU3RvcAogICAgICAgICAgICBXcml0ZS1Mb2cgIkRlbGV0ZWQ6ICRQYXRoIgogICAgICAgIH0KICAgIH0KICAgIGNhdGNoIHsKICAgICAgICBXcml0ZS1Mb2cgIkZhaWxlZCB0byBkZWxldGUgJyRQYXRoJzogJF8iICJXQVJOIgogICAgfQp9CgojID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09CiMgUGVuZGluZyBSZWJvb3QgRGV0ZWN0aW9uCiMgPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0KZnVuY3Rpb24gVGVzdC1QZW5kaW5nUmVib290IHsKICAgICRwZW5kaW5nID0gJGZhbHNlCgogICAgaWYgKFRlc3QtUGF0aCAiSEtMTTpcU09GVFdBUkVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cQ29tcG9uZW50IEJhc2VkIFNlcnZpY2luZ1xSZWJvb3RQZW5kaW5nIikgewogICAgICAgIFdyaXRlLUxvZyAiUGVuZGluZyByZWJvb3Q6IENCUyIgIldBUk4iOyAkcGVuZGluZyA9ICR0cnVlCiAgICB9CgogICAgaWYgKFRlc3QtUGF0aCAiSEtMTTpcU09GVFdBUkVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cV2luZG93c1VwZGF0ZVxBdXRvIFVwZGF0ZVxSZWJvb3RSZXF1aXJlZCIpIHsKICAgICAgICBXcml0ZS1Mb2cgIlBlbmRpbmcgcmVib290OiBXaW5kb3dzIFVwZGF0ZSIgIldBUk4iOyAkcGVuZGluZyA9ICR0cnVlCiAgICB9CgogICAgIyBMb2ctb25seSAoQ2hyb21lIHVwZGF0ZXMpCiAgICB0cnkgewogICAgICAgICR2YWx1ZSA9IEdldC1JdGVtUHJvcGVydHkgIkhLTE06XFNZU1RFTVxDdXJyZW50Q29udHJvbFNldFxDb250cm9sXFNlc3Npb24gTWFuYWdlciIgLU5hbWUgUGVuZGluZ0ZpbGVSZW5hbWVPcGVyYXRpb25zIC1FcnJvckFjdGlvbiBTaWxlbnRseUNvbnRpbnVlCiAgICAgICAgaWYgKCR2YWx1ZSkgewogICAgICAgICAgICBXcml0ZS1Mb2cgIlBlbmRpbmdGaWxlUmVuYW1lT3BlcmF0aW9ucyBwcmVzZW50IChpZ25vcmVkKSIgIklORk8iCiAgICAgICAgfQogICAgfSBjYXRjaCB7fQoKICAgIHJldHVybiAkcGVuZGluZwp9CgojID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09CiMgSW5zdGFsbGVyIEJ1c3kgRGV0ZWN0aW9uCiMgPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0KZnVuY3Rpb24gVGVzdC1JbnN0YWxsZXJCdXN5IHsKICAgICRidXN5ID0gJGZhbHNlCgogICAgdHJ5IHsKICAgICAgICAkcHJvY3MgPSBHZXQtQ2ltSW5zdGFuY2UgV2luMzJfUHJvY2VzcyAtRmlsdGVyICJOYW1lPSdtc2lleGVjLmV4ZSciIC1FcnJvckFjdGlvbiBTaWxlbnRseUNvbnRpbnVlCiAgICAgICAgJG5vdyA9IEdldC1EYXRlCgogICAgICAgIGZvcmVhY2ggKCRwIGluICRwcm9jcykgewogICAgICAgICAgICAkY21kID0gJHAuQ29tbWFuZExpbmUKICAgICAgICAgICAgCiAgICAgICAgICAgICMgQ2hlY2sgaWYgQ3JlYXRpb25EYXRlIGlzIHZhbGlkIGJlZm9yZSB1c2luZyBpdAogICAgICAgICAgICBpZiAoJHAuQ3JlYXRpb25EYXRlKSB7CiAgICAgICAgICAgICAgICB0cnkgewogICAgICAgICAgICAgICAgICAgICMgQ0lNIGFscmVhZHkgcmV0dXJucyBEYXRlVGltZSBvYmplY3RzLCBidXQgY2hlY2sgZm9yIGNvbnZlcnNpb24gaXNzdWVzCiAgICAgICAgICAgICAgICAgICAgJHN0YXJ0ZWQgPSAkcC5DcmVhdGlvbkRhdGUKICAgICAgICAgICAgICAgICAgICAkYWdlID0gKCRub3cgLSAkc3RhcnRlZCkuVG90YWxNaW51dGVzCiAgICAgICAgICAgICAgICAgICAgJHJlY2VudCA9ICRhZ2UgLWxlICRJbnN0YWxsZXJCdXN5TWludXRlcwogICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgY2F0Y2ggewogICAgICAgICAgICAgICAgICAgICMgRGF0ZSBjb252ZXJzaW9uIGZhaWxlZCwgYXNzdW1lIHJlY2VudCB0byBiZSBzYWZlCiAgICAgICAgICAgICAgICAgICAgV3JpdGUtTG9nICJDcmVhdGlvbkRhdGUgY29udmVyc2lvbiBmYWlsZWQgZm9yIG1zaWV4ZWMgUElEICQoJHAuUHJvY2Vzc0lkKSIgIldBUk4iCiAgICAgICAgICAgICAgICAgICAgJHJlY2VudCA9ICR0cnVlCiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgIH0KICAgICAgICAgICAgZWxzZSB7CiAgICAgICAgICAgICAgICAjIE5vIGNyZWF0aW9uIGRhdGUgYXZhaWxhYmxlLCBhc3N1bWUgcmVjZW50IHRvIGJlIHNhZmUKICAgICAgICAgICAgICAgICRyZWNlbnQgPSAkdHJ1ZQogICAgICAgICAgICB9CgogICAgICAgICAgICAkaW5zdGFsbExpa2UgPQogICAgICAgICAgICAgICAgKCRjbWQgLW1hdGNoICcvaScgLW9yCiAgICAgICAgICAgICAgICAgJGNtZCAtbWF0Y2ggJy94JyAtb3IKICAgICAgICAgICAgICAgICAkY21kIC1tYXRjaCAnL2YnIC1vcgogICAgICAgICAgICAgICAgICRjbWQgLW1hdGNoICcvdXBkYXRlJyAtb3IKICAgICAgICAgICAgICAgICAkY21kIC1tYXRjaCAnSU5TVEFMTCcgLW9yCiAgICAgICAgICAgICAgICAgJGNtZCAtbWF0Y2ggJ1VOSU5TVEFMTCcpCgogICAgICAgICAgICBpZiAoJHJlY2VudCAtYW5kICRpbnN0YWxsTGlrZSkgewogICAgICAgICAgICAgICAgV3JpdGUtTG9nICJJbnN0YWxsZXIgYnVzeTogUElEPSQoJHAuUHJvY2Vzc0lkKSBTdGFydGVkPSRzdGFydGVkIENtZD0kY21kIiAiV0FSTiIKICAgICAgICAgICAgICAgICRidXN5ID0gJHRydWUKICAgICAgICAgICAgfSBlbHNlIHsKICAgICAgICAgICAgICAgIFdyaXRlLUxvZyAiSWdub3JpbmcgbXNpZXhlYyBQSUQgJCgkcC5Qcm9jZXNzSWQpIChSZWNlbnQ9JHJlY2VudCBJbnN0YWxsQ21kPSRpbnN0YWxsTGlrZSkiICJJTkZPIgogICAgICAgICAgICB9CiAgICAgICAgfQogICAgfSBjYXRjaCB7CiAgICAgICAgV3JpdGUtTG9nICJUZXN0LUluc3RhbGxlckJ1c3kgZmFpbGVkOiAkXyIgIldBUk4iCiAgICB9CgogICAgIyBJbnN0YWxsZXJcSW5Qcm9ncmVzczogbG9nLW9ubHkKICAgIGlmIChUZXN0LVBhdGggIkhLTE06XFNPRlRXQVJFXE1pY3Jvc29mdFxXaW5kb3dzXEN1cnJlbnRWZXJzaW9uXEluc3RhbGxlclxJblByb2dyZXNzIikgewogICAgICAgIFdyaXRlLUxvZyAiSW5zdGFsbGVyIEluUHJvZ3Jlc3Mga2V5IHByZXNlbnQgKGlnbm9yZWQpIiAiSU5GTyIKICAgIH0KCiAgICByZXR1cm4gJGJ1c3kKfQoKIyA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PQojIE9mZmljZSBDMlIgQnVzeSBEZXRlY3Rpb24KIyA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PQpmdW5jdGlvbiBUZXN0LU9mZmljZUNsaWNrVG9SdW5CdXN5IHsKICAgICRidXN5ID0gJGZhbHNlCgogICAgdHJ5IHsKICAgICAgICAkcHJvY3MgPSBHZXQtQ2ltSW5zdGFuY2UgV2luMzJfUHJvY2VzcyAtRmlsdGVyICJOYW1lPSdzZXR1cC5leGUnIE9SIE5hbWU9J09mZmljZUMyUkNsaWVudC5leGUnIE9SIE5hbWU9J0ludGVncmF0ZWRPZmZpY2UuZXhlJyIgLUVycm9yQWN0aW9uIFNpbGVudGx5Q29udGludWUKCiAgICAgICAgZm9yZWFjaCAoJHAgaW4gJHByb2NzKSB7CiAgICAgICAgICAgICRjbWQgPSAkcC5Db21tYW5kTGluZQogICAgICAgICAgICBpZiAoJGNtZCAtbWF0Y2ggIk9mZmljZSIgLW9yICRjbWQgLW1hdGNoICJDbGlja1RvUnVuIiAtb3IgJGNtZCAtbWF0Y2ggIkMyUiIpIHsKICAgICAgICAgICAgICAgIFdyaXRlLUxvZyAiT2ZmaWNlIEMyUiBpbnN0YWxsL3JlcGFpciBkZXRlY3RlZDogUElEPSQoJHAuUHJvY2Vzc0lkKSBDbWQ9JGNtZCIgIldBUk4iCiAgICAgICAgICAgICAgICAkYnVzeSA9ICR0cnVlCiAgICAgICAgICAgIH0gZWxzZSB7CiAgICAgICAgICAgICAgICBXcml0ZS1Mb2cgIklnbm9yaW5nIHByb2Nlc3MgJCgkcC5OYW1lKSBQSUQgJCgkcC5Qcm9jZXNzSWQpIiAiSU5GTyIKICAgICAgICAgICAgfQogICAgICAgIH0KICAgIH0gY2F0Y2ggewogICAgICAgIFdyaXRlLUxvZyAiVGVzdC1PZmZpY2VDbGlja1RvUnVuQnVzeSBmYWlsZWQ6ICRfIiAiV0FSTiIKICAgIH0KCiAgICByZXR1cm4gJGJ1c3kKfQoKIyA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PQojIFJlc2V0IFNlcnZpY2VzCiMgPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0KZnVuY3Rpb24gUmVzZXQtSW5zdGFsbFNlcnZpY2VzIHsKICAgIFdyaXRlLUxvZyAiUmVzZXR0aW5nIGluc3RhbGxlci1yZWxhdGVkIHNlcnZpY2VzLi4uIgogICAgJGVycm9yID0gJGZhbHNlCgogICAgZm9yZWFjaCAoJHN2Y05hbWUgaW4gQCgibXNpc2VydmVyIiwiQ2xpY2tUb1J1blN2YyIpKSB7CiAgICAgICAgdHJ5IHsKICAgICAgICAgICAgJHN2YyA9IEdldC1TZXJ2aWNlIC1OYW1lICRzdmNOYW1lIC1FcnJvckFjdGlvbiBTaWxlbnRseUNvbnRpbnVlCiAgICAgICAgICAgIGlmICgtbm90ICRzdmMpIHsgV3JpdGUtTG9nICIkc3ZjTmFtZSBub3QgcHJlc2VudCIgIklORk8iOyBjb250aW51ZSB9CgogICAgICAgICAgICBpZiAoJHN2Yy5TdGF0dXMgLWVxICJSdW5uaW5nIikgewogICAgICAgICAgICAgICAgV3JpdGUtTG9nICJSZXN0YXJ0aW5nICRzdmNOYW1lIgogICAgICAgICAgICAgICAgaWYgKC1ub3QgJFdoYXRJZikgeyBSZXN0YXJ0LVNlcnZpY2UgJHN2Y05hbWUgLUZvcmNlIH0KICAgICAgICAgICAgfSBlbHNlIHsKICAgICAgICAgICAgICAgIFdyaXRlLUxvZyAiU3RhcnRpbmcgJHN2Y05hbWUiCiAgICAgICAgICAgICAgICBpZiAoLW5vdCAkV2hhdElmKSB7IFN0YXJ0LVNlcnZpY2UgJHN2Y05hbWUgfQogICAgICAgICAgICB9CiAgICAgICAgfQogICAgICAgIGNhdGNoIHsKICAgICAgICAgICAgV3JpdGUtTG9nICJTZXJ2aWNlIHJlc2V0IGZhaWxlZCBmb3IgJHtzdmNOYW1lfTogJF8iICJXQVJOIgogICAgICAgICAgICAkZXJyb3IgPSAkdHJ1ZQogICAgICAgIH0KICAgIH0KICAgIHJldHVybiAkZXJyb3IKfQoKIyA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PQojIENsZWFudXAgRnVuY3Rpb25zCiMgPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0KZnVuY3Rpb24gQ2xlYXItVGVtcEZvbGRlcnMgewogICAgV3JpdGUtTG9nICJDbGVhcmluZyB0ZW1wIGZvbGRlcnMuLi4iCiAgICAkcGF0aHMgPSBAKCRlbnY6VEVNUCwgJGVudjpUTVAsICJDOlxXaW5kb3dzXFRlbXAiKSB8IFdoZXJlLU9iamVjdCB7ICRfIC1hbmQgKFRlc3QtUGF0aCAkXykgfQogICAgZm9yZWFjaCAoJHBhdGggaW4gJHBhdGhzKSB7CiAgICAgICAgR2V0LUNoaWxkSXRlbSAkcGF0aCAtRm9yY2UgLUVycm9yQWN0aW9uIFNpbGVudGx5Q29udGludWUgfCBGb3JFYWNoLU9iamVjdCB7CiAgICAgICAgICAgIFJlbW92ZS1JdGVtU2FmZSAkXy5GdWxsTmFtZSAtUmVjdXJzZQogICAgICAgIH0KICAgIH0KfQoKZnVuY3Rpb24gQ2xlYXItVXNlclByb2ZpbGVUZW1wRm9sZGVycyB7CiAgICBXcml0ZS1Mb2cgIkNsZWFyaW5nIGFsbCB1c2VyIHByb2ZpbGUgdGVtcCBmb2xkZXJzLi4uIgogICAgJHByb2ZpbGVzID0gR2V0LUNoaWxkSXRlbSAiQzpcVXNlcnMiIC1EaXJlY3RvcnkgLUVycm9yQWN0aW9uIFNpbGVudGx5Q29udGludWUgfAogICAgICAgIFdoZXJlLU9iamVjdCB7ICRfLk5hbWUgLW5vdGluICJQdWJsaWMiLCJEZWZhdWx0IiwiRGVmYXVsdCBVc2VyIiwiQWxsIFVzZXJzIiB9CgogICAgZm9yZWFjaCAoJHByb2ZpbGUgaW4gJHByb2ZpbGVzKSB7CiAgICAgICAgJHRlbXBQYXRoID0gSm9pbi1QYXRoICRwcm9maWxlLkZ1bGxOYW1lICJBcHBEYXRhXExvY2FsXFRlbXAiCiAgICAgICAgaWYgKFRlc3QtUGF0aCAkdGVtcFBhdGgpIHsKICAgICAgICAgICAgR2V0LUNoaWxkSXRlbSAkdGVtcFBhdGggLUZvcmNlIC1FcnJvckFjdGlvbiBTaWxlbnRseUNvbnRpbnVlIHwgRm9yRWFjaC1PYmplY3QgewogICAgICAgICAgICAgICAgUmVtb3ZlLUl0ZW1TYWZlICRfLkZ1bGxOYW1lIC1SZWN1cnNlCiAgICAgICAgICAgIH0KICAgICAgICB9CiAgICB9Cn0KCmZ1bmN0aW9uIENsZWFyLVdpbmRvd3NVcGRhdGVDYWNoZSB7CiAgICBXcml0ZS1Mb2cgIkNsZWFyaW5nIFdpbmRvd3MgVXBkYXRlIGNhY2hlLi4uIgogICAgJHBhdGggPSAiQzpcV2luZG93c1xTb2Z0d2FyZURpc3RyaWJ1dGlvblxEb3dubG9hZCIKCiAgICAkc3ZjTmFtZXMgPSBAKCJ3dWF1c2VydiIsImJpdHMiKQogICAgJHN0b3BwZWQgPSBAKCkKCiAgICBmb3JlYWNoICgkc3ZjIGluICRzdmNOYW1lcykgewogICAgICAgIHRyeSB7CiAgICAgICAgICAgIGlmICgoR2V0LVNlcnZpY2UgJHN2YyAtRXJyb3JBY3Rpb24gU2lsZW50bHlDb250aW51ZSkuU3RhdHVzIC1lcSAiUnVubmluZyIpIHsKICAgICAgICAgICAgICAgIFdyaXRlLUxvZyAiU3RvcHBpbmcgJHN2YyIKICAgICAgICAgICAgICAgIGlmICgtbm90ICRXaGF0SWYpIHsKICAgICAgICAgICAgICAgICAgICBTdG9wLVNlcnZpY2UgJHN2YyAtRm9yY2UKICAgICAgICAgICAgICAgICAgICAkc3RvcHBlZCArPSAkc3ZjCiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgIH0KICAgICAgICB9IGNhdGNoIHt9CiAgICB9CgogICAgaWYgKFRlc3QtUGF0aCAkcGF0aCkgewogICAgICAgIEdldC1DaGlsZEl0ZW0gJHBhdGggLUZvcmNlIC1FcnJvckFjdGlvbiBTaWxlbnRseUNvbnRpbnVlIHwgRm9yRWFjaC1PYmplY3QgewogICAgICAgICAgICBSZW1vdmUtSXRlbVNhZmUgJF8uRnVsbE5hbWUgLVJlY3Vyc2UKICAgICAgICB9CiAgICB9CgogICAgZm9yZWFjaCAoJHN2YyBpbiAkc3RvcHBlZCkgewogICAgICAgIFdyaXRlLUxvZyAiUmVzdGFydGluZyAkc3ZjIgogICAgICAgIGlmICgtbm90ICRXaGF0SWYpIHsgU3RhcnQtU2VydmljZSAkc3ZjIH0KICAgIH0KfQoKZnVuY3Rpb24gQ2xlYXItRGVsaXZlcnlPcHRpbWl6YXRpb25DYWNoZSB7CiAgICBXcml0ZS1Mb2cgIkNsZWFyaW5nIERlbGl2ZXJ5IE9wdGltaXphdGlvbiBjYWNoZS4uLiIKICAgICRwYXRoID0gIkM6XFByb2dyYW1EYXRhXE1pY3Jvc29mdFxXaW5kb3dzXERlbGl2ZXJ5T3B0aW1pemF0aW9uXENhY2hlIgoKICAgIGlmIChUZXN0LVBhdGggJHBhdGgpIHsKICAgICAgICBHZXQtQ2hpbGRJdGVtICRwYXRoIC1Gb3JjZSAtRXJyb3JBY3Rpb24gU2lsZW50bHlDb250aW51ZSB8IEZvckVhY2gtT2JqZWN0IHsKICAgICAgICAgICAgUmVtb3ZlLUl0ZW1TYWZlICRfLkZ1bGxOYW1lIC1SZWN1cnNlCiAgICAgICAgfQogICAgfQp9CgpmdW5jdGlvbiBDbGVhci1PZmZpY2VDbGlja1RvUnVuSnVuayB7CiAgICBXcml0ZS1Mb2cgIkNsZWFyaW5nIE9mZmljZSBDbGljay10by1SdW4gbG9ncyBhbmQgdGVsZW1ldHJ5Li4uIgoKICAgICRwYXRocyA9IEAoCiAgICAgICAgIkM6XFByb2dyYW1EYXRhXE1pY3Jvc29mdFxPZmZpY2VcQ2xpY2tUb1J1blxMb2ciLAogICAgICAgICJDOlxQcm9ncmFtRGF0YVxNaWNyb3NvZnRcT2ZmaWNlXENsaWNrVG9SdW5cVGVsZW1ldHJ5IiwKICAgICAgICAiQzpcUHJvZ3JhbURhdGFcTWljcm9zb2Z0XENsaWNrVG9SdW5cTG9nIiwKICAgICAgICAiQzpcUHJvZ3JhbURhdGFcTWljcm9zb2Z0XENsaWNrVG9SdW5cVGVsZW1ldHJ5IiwKICAgICAgICAiQzpcUHJvZ3JhbURhdGFcTWljcm9zb2Z0XE9mZmljZVxDbGlja1RvUnVuXExvZ3MiLAogICAgICAgICJDOlxQcm9ncmFtRGF0YVxNaWNyb3NvZnRcQ2xpY2tUb1J1blxMb2dzIgogICAgKQoKICAgIGZvcmVhY2ggKCRwYXRoIGluICRwYXRocykgewogICAgICAgIGlmIChUZXN0LVBhdGggJHBhdGgpIHsKICAgICAgICAgICAgR2V0LUNoaWxkSXRlbSAkcGF0aCAtRm9yY2UgLUVycm9yQWN0aW9uIFNpbGVudGx5Q29udGludWUgfCBGb3JFYWNoLU9iamVjdCB7CiAgICAgICAgICAgICAgICBSZW1vdmUtSXRlbVNhZmUgJF8uRnVsbE5hbWUgLVJlY3Vyc2UKICAgICAgICAgICAgfQogICAgICAgIH0KICAgIH0KCiAgICAjIFBlci11c2VyIE9mZmljZSBjYWNoZQogICAgJGxvY2FsQmFzZSA9IEpvaW4tUGF0aCAkZW52OkxPQ0FMQVBQREFUQSAiTWljcm9zb2Z0XE9mZmljZVwxNi4wIgogICAgJHN1YlBhdGhzID0gIk9mZmljZUZpbGVDYWNoZSIsIldlZiIsIlRlbGVtZXRyeSIsIkx5bmNcVHJhY2luZyIKCiAgICBmb3JlYWNoICgkc3ViIGluICRzdWJQYXRocykgewogICAgICAgICRmdWxsID0gSm9pbi1QYXRoICRsb2NhbEJhc2UgJHN1YgogICAgICAgIGlmIChUZXN0LVBhdGggJGZ1bGwpIHsKICAgICAgICAgICAgR2V0LUNoaWxkSXRlbSAkZnVsbCAtRm9yY2UgLUVycm9yQWN0aW9uIFNpbGVudGx5Q29udGludWUgfCBGb3JFYWNoLU9iamVjdCB7CiAgICAgICAgICAgICAgICBSZW1vdmUtSXRlbVNhZmUgJF8uRnVsbE5hbWUgLVJlY3Vyc2UKICAgICAgICAgICAgfQogICAgICAgIH0KICAgIH0KfQoKZnVuY3Rpb24gQ2xlYXItT2xkU3lzdGVtTG9ncyB7CiAgICBXcml0ZS1Mb2cgIkNsZWFyaW5nIENCUy9ESVNNL01vU2V0dXAgbG9ncy4uLiIKICAgICRwYXR0ZXJucyA9IEAoCiAgICAgICAgIkM6XFdpbmRvd3NcTG9nc1xDQlNcKi5jYWIiLAogICAgICAgICJDOlxXaW5kb3dzXExvZ3NcQ0JTXENic1BlcnNpc3RfKi5sb2ciLAogICAgICAgICJDOlxXaW5kb3dzXExvZ3NcRElTTVwqLmxvZy5vbGQiLAogICAgICAgICJDOlxXaW5kb3dzXExvZ3NcTW9TZXR1cFwqLmxvZyIKICAgICkKICAgIGZvcmVhY2ggKCRwYXR0ZXJuIGluICRwYXR0ZXJucykgewogICAgICAgIEdldC1DaGlsZEl0ZW0gJHBhdHRlcm4gLUZvcmNlIC1FcnJvckFjdGlvbiBTaWxlbnRseUNvbnRpbnVlIHwgRm9yRWFjaC1PYmplY3QgewogICAgICAgICAgICBSZW1vdmUtSXRlbVNhZmUgJF8uRnVsbE5hbWUKICAgICAgICB9CiAgICB9Cn0KCmZ1bmN0aW9uIENsZWFyLVdpbmRvd3NJbnN0YWxsZXJMb2dzIHsKICAgIFdyaXRlLUxvZyAiQ2xlYXJpbmcgV2luZG93cyBJbnN0YWxsZXIgbG9ncy90ZW1wLi4uIgogICAgJHJvb3QgPSAiQzpcV2luZG93c1xJbnN0YWxsZXIiCiAgICBpZiAoVGVzdC1QYXRoICRyb290KSB7CiAgICAgICAgR2V0LUNoaWxkSXRlbSAkcm9vdCAtRmlsdGVyICIqLmxvZyIgLUZvcmNlIC1FcnJvckFjdGlvbiBTaWxlbnRseUNvbnRpbnVlIHwgRm9yRWFjaC1PYmplY3QgewogICAgICAgICAgICBSZW1vdmUtSXRlbVNhZmUgJF8uRnVsbE5hbWUKICAgICAgICB9CiAgICAgICAgR2V0LUNoaWxkSXRlbSAkcm9vdCAtRmlsdGVyICIqLnRtcCIgLUZvcmNlIC1FcnJvckFjdGlvbiBTaWxlbnRseUNvbnRpbnVlIHwgRm9yRWFjaC1PYmplY3QgewogICAgICAgICAgICBSZW1vdmUtSXRlbVNhZmUgJF8uRnVsbE5hbWUKICAgICAgICB9CiAgICB9Cn0KCmZ1bmN0aW9uIENsZWFyLVJlY3ljbGVCaW5TYWZlIHsKICAgIGlmICgkU2tpcFJlY3ljbGVCaW4pIHsKICAgICAgICBXcml0ZS1Mb2cgIlNraXBwaW5nIFJlY3ljbGUgQmluIGNsZWFudXAgKFNraXBSZWN5Y2xlQmluIHVzZWQpIgogICAgICAgIHJldHVybgogICAgfQoKICAgIFdyaXRlLUxvZyAiQ2xlYXJpbmcgUmVjeWNsZSBCaW4uLi4iCgogICAgdHJ5IHsKICAgICAgICBpZiAoJFdoYXRJZikgewogICAgICAgICAgICBXcml0ZS1Mb2cgIldoYXRJZjogV291bGQgY2xlYXIgUmVjeWNsZSBCaW4iCiAgICAgICAgfSBlbHNlIHsKICAgICAgICAgICAgQ2xlYXItUmVjeWNsZUJpbiAtRm9yY2UgLUVycm9yQWN0aW9uIFNpbGVudGx5Q29udGludWUKICAgICAgICB9CiAgICB9IGNhdGNoIHsKICAgICAgICBXcml0ZS1Mb2cgIlJlY3ljbGUgQmluIGNsZWFudXAgZmFpbGVkOiAkXyIgIldBUk4iCiAgICB9Cn0KCmZ1bmN0aW9uIEludm9rZS1BZ2dyZXNzaXZlQ2xlYW51cCB7CiAgICBXcml0ZS1Mb2cgIlJ1bm5pbmcgYWdncmVzc2l2ZSBjbGVhbnVwLi4uIgogICAgJHdlciA9ICJDOlxQcm9ncmFtRGF0YVxNaWNyb3NvZnRcV2luZG93c1xXRVIiCiAgICBpZiAoVGVzdC1QYXRoICR3ZXIpIHsKICAgICAgICBHZXQtQ2hpbGRJdGVtICR3ZXIgLVJlY3Vyc2UgLUZvcmNlIC1FcnJvckFjdGlvbiBTaWxlbnRseUNvbnRpbnVlIHwgRm9yRWFjaC1PYmplY3QgewogICAgICAgICAgICBSZW1vdmUtSXRlbVNhZmUgJF8uRnVsbE5hbWUgLVJlY3Vyc2UKICAgICAgICB9CiAgICB9Cn0KCiMgPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0KIyBNQUlOIEVYRUNVVElPTgojID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09CiRleGl0Q29kZSA9IDAKCmlmICgtbm90ICRTa2lwUHJlZmxpZ2h0KSB7CgogICAgaWYgKFRlc3QtUGVuZGluZ1JlYm9vdCkgewogICAgICAgIFdyaXRlLUxvZyAiUHJlLWZsaWdodCBGQUlMRUQ6IFBlbmRpbmcgcmVib290IiAiV0FSTiIKICAgICAgICAkZXhpdENvZGUgPSAyMAogICAgfQoKICAgIGlmIChUZXN0LUluc3RhbGxlckJ1c3kpIHsKICAgICAgICBXcml0ZS1Mb2cgIlByZS1mbGlnaHQgRkFJTEVEOiBJbnN0YWxsZXIgYnVzeSIgIldBUk4iCiAgICAgICAgaWYgKCRleGl0Q29kZSAtZXEgMCkgeyAkZXhpdENvZGUgPSAyMSB9CiAgICB9CgogICAgaWYgKFRlc3QtT2ZmaWNlQ2xpY2tUb1J1bkJ1c3kpIHsKICAgICAgICBXcml0ZS1Mb2cgIlByZS1mbGlnaHQgRkFJTEVEOiBPZmZpY2UgQzJSIGJ1c3kiICJXQVJOIgogICAgICAgIGlmICgkZXhpdENvZGUgLWVxIDApIHsgJGV4aXRDb2RlID0gMjIgfQogICAgfQoKICAgIGlmICgkZXhpdENvZGUgLWVxIDApIHsKICAgICAgICAkc3ZjRXJyb3JzID0gUmVzZXQtSW5zdGFsbFNlcnZpY2VzCiAgICAgICAgaWYgKCRzdmNFcnJvcnMpIHsKICAgICAgICAgICAgV3JpdGUtTG9nICJQcmUtZmxpZ2h0IEZBSUxFRDogU2VydmljZSByZXN0YXJ0IGlzc3VlIiAiV0FSTiIKICAgICAgICAgICAgJGV4aXRDb2RlID0gMjMKICAgICAgICB9CiAgICB9CgogICAgaWYgKCRleGl0Q29kZSAtbmUgMCkgewogICAgICAgIFdyaXRlLUxvZyAiUHJlLWZsaWdodCBmYWlsZWQuIEV4aXRDb2RlPSRleGl0Q29kZSIKICAgICAgICBXcml0ZS1Mb2cgIj09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0iCiAgICAgICAgZXhpdCAkZXhpdENvZGUKICAgIH0KCiAgICBXcml0ZS1Mb2cgIlByZS1mbGlnaHQgY2hlY2tzIHBhc3NlZC4gUHJvY2VlZGluZyB3aXRoIGNsZWFudXAuLi4iCn0KZWxzZSB7CiAgICBXcml0ZS1Mb2cgIlNraXBQcmVmbGlnaHQgdXNlZCDigJQgcGVyZm9ybWluZyBjbGVhbnVwIG9ubHkiCn0KCiMgPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0KIyBSVU4gQ0xFQU5VUAojID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09CnRyeSB7CiAgICBDbGVhci1UZW1wRm9sZGVycwogICAgQ2xlYXItVXNlclByb2ZpbGVUZW1wRm9sZGVycwogICAgQ2xlYXItV2luZG93c1VwZGF0ZUNhY2hlCiAgICBDbGVhci1EZWxpdmVyeU9wdGltaXphdGlvbkNhY2hlCiAgICBDbGVhci1PZmZpY2VDbGlja1RvUnVuSnVuawogICAgQ2xlYXItT2xkU3lzdGVtTG9ncwogICAgQ2xlYXItV2luZG93c0luc3RhbGxlckxvZ3MKICAgIENsZWFyLVJlY3ljbGVCaW5TYWZlCgogICAgaWYgKCRBZ2dyZXNzaXZlKSB7CiAgICAgICAgSW52b2tlLUFnZ3Jlc3NpdmVDbGVhbnVwCiAgICB9Cn0KY2F0Y2ggewogICAgV3JpdGUtTG9nICJVbmV4cGVjdGVkIGNsZWFudXAgZXJyb3I6ICRfIiAiRVJST1IiCiAgICBpZiAoJGV4aXRDb2RlIC1lcSAwKSB7ICRleGl0Q29kZSA9IDEgfQp9CgojID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09CiMgRklOQUwgU1BBQ0UgQ0FMQwojID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09CiRmaW5hbEZyZWUgPSBHZXQtU3lzdGVtRHJpdmVGcmVlU3BhY2UKJGRlbHRhID0gJGZpbmFsRnJlZSAtICRpbml0aWFsRnJlZQoKaWYgKCRkZWx0YSAtbHQgMCkgewogICAgV3JpdGUtTG9nICJTWVNURU0gQ0hVUk46IEZyZWUgc3BhY2UgZGVjcmVhc2VkIGJ5ICQoRm9ybWF0LUJ5dGVzIChbbWF0aF06OkFicygkZGVsdGEpKSkgZHVyaW5nIHJ1bi4gUmVwb3J0aW5nIDAgQiByZWNsYWltZWQuIiAiSU5GTyIKICAgICRkZWx0YVNob3duID0gMAp9CmVsc2UgewogICAgJGRlbHRhU2hvd24gPSAkZGVsdGEKfQoKV3JpdGUtTG9nICJGaW5hbCBmcmVlIHNwYWNlOiAkKEZvcm1hdC1CeXRlcyAkZmluYWxGcmVlKSIKV3JpdGUtTG9nICJTcGFjZSByZWNsYWltZWQ6ICQoRm9ybWF0LUJ5dGVzICRkZWx0YVNob3duKSIKV3JpdGUtTG9nICJFeGl0Q29kZTogJGV4aXRDb2RlIgpXcml0ZS1Mb2cgIkxvZyBmaWxlOiAkc2NyaXB0OkxvZ0ZpbGUiCldyaXRlLUxvZyAiPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PSIKCmlmICgtbm90ICRTaWxlbnQpIHsKICAgIFdyaXRlLUhvc3QgIiIKICAgIFdyaXRlLUhvc3QgIkNsZWFudXAgY29tcGxldGUuIiAtRm9yZWdyb3VuZENvbG9yIEN5YW4KICAgIFdyaXRlLUhvc3QgIlJlY2xhaW1lZDogJChGb3JtYXQtQnl0ZXMgJGRlbHRhU2hvd24pIiAtRm9yZWdyb3VuZENvbG9yIEN5YW4KICAgIFdyaXRlLUhvc3QgIkxvZyBmaWxlOiAkc2NyaXB0OkxvZ0ZpbGUiIC1Gb3JlZ3JvdW5kQ29sb3IgRGFya0dyYXkKfQoKZXhpdCAkZXhpdENvZGUK'

$script:CleanupScriptContent = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($script:CleanupScriptBase64))

# ================================
# INITIALIZATION
# ================================
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName System.Windows.Forms

$script:LogPath = $null
$script:RunspacePool = $null
$script:CleanupRunspace = $null
$script:StartTime = $null
$script:Timer = $null

# ================================
# ADMIN CHECK & ELEVATION
# ================================
function Test-IsAdmin {
    $wid = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($wid)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Start-ElevatedProcess {
    $scriptPath = $MyInvocation.ScriptName
    if (-not $scriptPath) { $scriptPath = $PSCommandPath }
    
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = "powershell.exe"
        $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""
        $psi.Verb = "runas"
        $psi.UseShellExecute = $true
        
        [System.Diagnostics.Process]::Start($psi) | Out-Null
        exit 0
    }
    catch {
        [System.Windows.MessageBox]::Show(
            "Failed to elevate to administrator.`n`nError: $_",
            "Elevation Failed",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Error
        )
        exit 1
    }
}

if (-not (Test-IsAdmin)) {
    Start-ElevatedProcess
}

# ================================
# XAML DEFINITION
# ================================
$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="OS Cleanup Utility" 
        Height="750" Width="900"
        WindowStartupLocation="CenterScreen"
        ResizeMode="CanResize"
        Background="#F5F5F5">
    
    <Window.Resources>
        <Style x:Key="ModernButton" TargetType="Button">
            <Setter Property="Background" Value="#0078D4"/>
            <Setter Property="Foreground" Value="White"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Padding" Value="12,6"/>
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border Background="{TemplateBinding Background}" 
                                CornerRadius="3"
                                BorderThickness="0">
                            <ContentPresenter HorizontalAlignment="Center" 
                                            VerticalAlignment="Center"/>
                        </Border>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
            <Style.Triggers>
                <Trigger Property="IsMouseOver" Value="True">
                    <Setter Property="Background" Value="#005A9E"/>
                </Trigger>
                <Trigger Property="IsEnabled" Value="False">
                    <Setter Property="Background" Value="#CCCCCC"/>
                    <Setter Property="Foreground" Value="#666666"/>
                </Trigger>
            </Style.Triggers>
        </Style>

        <Style x:Key="SecondaryButton" TargetType="Button" BasedOn="{StaticResource ModernButton}">
            <Setter Property="Background" Value="#6C757D"/>
            <Style.Triggers>
                <Trigger Property="IsMouseOver" Value="True">
                    <Setter Property="Background" Value="#545B62"/>
                </Trigger>
            </Style.Triggers>
        </Style>

        <Style x:Key="SuccessButton" TargetType="Button" BasedOn="{StaticResource ModernButton}">
            <Setter Property="Background" Value="#28A745"/>
            <Style.Triggers>
                <Trigger Property="IsMouseOver" Value="True">
                    <Setter Property="Background" Value="#218838"/>
                </Trigger>
            </Style.Triggers>
        </Style>
    </Window.Resources>

    <Grid Margin="15">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <!-- Header -->
        <Border Grid.Row="0" Background="White" Padding="15" CornerRadius="5" Margin="0,0,0,10">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>
                
                <StackPanel Grid.Column="0">
                    <TextBlock Text="Windows OS Cleanup Utility" 
                               FontSize="20" 
                               FontWeight="Bold" 
                               Foreground="#2C3E50"/>
                    <TextBlock Text="Safely clean temporary files and perform system maintenance" 
                               FontSize="12" 
                               Foreground="#7F8C8D"
                               Margin="0,3,0,0"/>
                </StackPanel>

                <StackPanel Grid.Column="1" VerticalAlignment="Center">
                    <TextBlock Name="AdminBadge" 
                               Text="⚡ Administrator" 
                               FontSize="11" 
                               FontWeight="Bold"
                               Foreground="#E74C3C"
                               Background="#FFE6E6"
                               Padding="8,4"
                               HorizontalAlignment="Right"/>
                </StackPanel>
            </Grid>
        </Border>

        <!-- Options Panel -->
        <Border Grid.Row="1" Background="White" Padding="15" CornerRadius="5" Margin="0,0,0,10">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="*"/>
                </Grid.ColumnDefinitions>

                <StackPanel Grid.Column="0" Margin="0,0,10,0">
                    <TextBlock Text="Cleanup Options" 
                               FontSize="13" 
                               FontWeight="SemiBold" 
                               Foreground="#34495E"
                               Margin="0,0,0,8"/>
                    
                    <CheckBox Name="chkAggressive" 
                              Content="Aggressive cleanup (includes WER data)" 
                              Margin="0,0,0,6"
                              ToolTip="Enables additional cleanup including Windows Error Reporting data"/>
                    
                    <CheckBox Name="chkSkipRecycleBin" 
                              Content="Skip Recycle Bin cleanup" 
                              Margin="0,0,0,6"
                              ToolTip="Preserve Recycle Bin contents"/>
                    
                    <CheckBox Name="chkSkipPreflight" 
                              Content="Skip preflight checks" 
                              Margin="0,0,0,6"
                              ToolTip="Bypass reboot and installer busy detection"/>
                    
                    <CheckBox Name="chkWhatIf" 
                              Content="WhatIf mode (dry run)" 
                              Margin="0,0,0,6"
                              ToolTip="Show what would be deleted without making changes"/>
                </StackPanel>

                <StackPanel Grid.Column="1" Margin="10,0,0,0">
                    <TextBlock Text="Advanced Settings" 
                               FontSize="13" 
                               FontWeight="SemiBold" 
                               Foreground="#34495E"
                               Margin="0,0,0,8"/>
                    
                    <TextBlock Text="Installer busy threshold (minutes):" 
                               FontSize="11" 
                               Foreground="#7F8C8D"
                               Margin="0,0,0,4"/>
                    
                    <Grid Margin="0,0,0,10">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="Auto"/>
                        </Grid.ColumnDefinitions>
                        <Slider Name="sliderInstallerMinutes" 
                                Grid.Column="0"
                                Minimum="30" 
                                Maximum="240" 
                                Value="120" 
                                TickFrequency="30"
                                IsSnapToTickEnabled="True"
                                VerticalAlignment="Center"/>
                        <TextBlock Name="txtInstallerMinutes" 
                                   Grid.Column="1"
                                   Text="120" 
                                   FontWeight="Bold"
                                   Foreground="#0078D4"
                                   Width="40"
                                   TextAlignment="Right"
                                   VerticalAlignment="Center"
                                   Margin="10,0,0,0"/>
                    </Grid>

                    <CheckBox Name="chkAutoScroll" 
                              Content="Auto-scroll log output" 
                              IsChecked="True"
                              Margin="0,0,0,6"
                              ToolTip="Automatically scroll to latest log entries"/>
                </StackPanel>
            </Grid>
        </Border>

        <!-- Log Display -->
        <Border Grid.Row="2" Background="White" Padding="0" CornerRadius="5" Margin="0,0,0,10">
            <Grid>
                <Grid.RowDefinitions>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="*"/>
                </Grid.RowDefinitions>

                <Border Grid.Row="0" 
                        Background="#34495E" 
                        Padding="10,8"
                        CornerRadius="5,5,0,0">
                    <Grid>
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="Auto"/>
                        </Grid.ColumnDefinitions>
                        
                        <TextBlock Grid.Column="0"
                                   Text="Operation Log" 
                                   FontSize="12" 
                                   FontWeight="SemiBold" 
                                   Foreground="White"/>
                        
                        <Button Grid.Column="1"
                                Name="btnClearLog"
                                Content="Clear Log"
                                FontSize="10"
                                Padding="8,3"
                                Background="#546E7A"
                                Foreground="White"
                                BorderThickness="0"
                                Cursor="Hand"/>
                    </Grid>
                </Border>

                <TextBox Name="txtLog" 
                         Grid.Row="1"
                         IsReadOnly="True"
                         VerticalScrollBarVisibility="Auto"
                         HorizontalScrollBarVisibility="Auto"
                         FontFamily="Consolas"
                         FontSize="11"
                         Background="#1E1E1E"
                         Foreground="#D4D4D4"
                         Padding="10"
                         TextWrapping="NoWrap"
                         BorderThickness="0"/>
            </Grid>
        </Border>

        <!-- Status Bar -->
        <Border Grid.Row="3" Background="White" Padding="12" CornerRadius="5" Margin="0,0,0,10">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>

                <StackPanel Grid.Column="0" Orientation="Horizontal" VerticalAlignment="Center">
                    <TextBlock Text="Status:" 
                               FontSize="11" 
                               Foreground="#7F8C8D" 
                               VerticalAlignment="Center"
                               Margin="0,0,8,0"/>
                    <TextBlock Name="txtStatus" 
                               Text="Ready" 
                               FontSize="11" 
                               FontWeight="SemiBold"
                               Foreground="#2ECC71"
                               VerticalAlignment="Center"/>
                </StackPanel>

                <ProgressBar Grid.Column="1" 
                             Name="progressBar" 
                             Height="6" 
                             Margin="15,0"
                             IsIndeterminate="False"
                             Visibility="Collapsed"/>

                <StackPanel Grid.Column="2" Orientation="Horizontal" VerticalAlignment="Center">
                    <TextBlock Name="txtSpaceReclaimed" 
                               Text="" 
                               FontSize="11"
                               FontWeight="Bold"
                               Foreground="#0078D4"
                               VerticalAlignment="Center"
                               Margin="0,0,10,0"/>
                    <TextBlock Name="txtElapsedTime" 
                               Text="" 
                               FontSize="10" 
                               Foreground="#95A5A6"
                               VerticalAlignment="Center"/>
                </StackPanel>
            </Grid>
        </Border>

        <!-- Action Buttons -->
        <Grid Grid.Row="4">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="Auto"/>
                <ColumnDefinition Width="Auto"/>
                <ColumnDefinition Width="Auto"/>
            </Grid.ColumnDefinitions>

            <Button Grid.Column="1"
                    Name="btnRun"
                    Content="▶ Run Cleanup"
                    Style="{StaticResource SuccessButton}"
                    Width="140"
                    Height="35"
                    Margin="0,0,8,0"/>

            <Button Grid.Column="2"
                    Name="btnStop"
                    Content="⏹ Stop"
                    Style="{StaticResource SecondaryButton}"
                    Width="100"
                    Height="35"
                    IsEnabled="False"
                    Margin="0,0,8,0"/>

            <Button Grid.Column="3"
                    Name="btnOpenLog"
                    Content="📄 Open Log File"
                    Style="{StaticResource ModernButton}"
                    Width="130"
                    Height="35"/>
        </Grid>
    </Grid>
</Window>
"@

# ================================
# LOAD XAML
# ================================
try {
    $reader = [System.Xml.XmlReader]::Create([System.IO.StringReader]::new($xaml))
    $window = [Windows.Markup.XamlReader]::Load($reader)
}
catch {
    [System.Windows.MessageBox]::Show(
        "Failed to load GUI.`n`nError: $_",
        "Critical Error",
        [System.Windows.MessageBoxButton]::OK,
        [System.Windows.MessageBoxImage]::Error
    )
    exit 1
}

# ================================
# GET CONTROLS
# ================================
$controls = @{
    chkAggressive        = $window.FindName("chkAggressive")
    chkSkipRecycleBin    = $window.FindName("chkSkipRecycleBin")
    chkSkipPreflight     = $window.FindName("chkSkipPreflight")
    chkWhatIf            = $window.FindName("chkWhatIf")
    chkAutoScroll        = $window.FindName("chkAutoScroll")
    sliderInstallerMinutes = $window.FindName("sliderInstallerMinutes")
    txtInstallerMinutes  = $window.FindName("txtInstallerMinutes")
    txtLog               = $window.FindName("txtLog")
    txtStatus            = $window.FindName("txtStatus")
    txtSpaceReclaimed    = $window.FindName("txtSpaceReclaimed")
    txtElapsedTime       = $window.FindName("txtElapsedTime")
    progressBar          = $window.FindName("progressBar")
    btnRun               = $window.FindName("btnRun")
    btnStop              = $window.FindName("btnStop")
    btnOpenLog           = $window.FindName("btnOpenLog")
    btnClearLog          = $window.FindName("btnClearLog")
}

# ================================
# HELPER FUNCTIONS
# ================================
function Write-GuiLog {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Message,
        [string]$Color = "#D4D4D4"
    )
    
    $window.Dispatcher.Invoke([action]{
        $timestamp = Get-Date -Format "HH:mm:ss"
        $controls.txtLog.AppendText("[$timestamp] $Message`r`n")
        
        if ($controls.chkAutoScroll.IsChecked) {
            $controls.txtLog.ScrollToEnd()
        }
    })
}

function Update-Status {
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        [string]$Color = "#2ECC71"
    )
    
    $window.Dispatcher.Invoke([action]{
        $controls.txtStatus.Text = $Message
        $controls.txtStatus.Foreground = $Color
    })
}

function Update-ElapsedTime {
    if ($script:StartTime) {
        $elapsed = (Get-Date) - $script:StartTime
        $timeStr = "{0:mm}:{0:ss}" -f $elapsed
        
        $window.Dispatcher.Invoke([action]{
            $controls.txtElapsedTime.Text = "⏱ $timeStr"
        })
    }
}

function Enable-Controls {
    param([bool]$Enabled)
    
    $window.Dispatcher.Invoke([action]{
        $controls.chkAggressive.IsEnabled = $Enabled
        $controls.chkSkipRecycleBin.IsEnabled = $Enabled
        $controls.chkSkipPreflight.IsEnabled = $Enabled
        $controls.chkWhatIf.IsEnabled = $Enabled
        $controls.sliderInstallerMinutes.IsEnabled = $Enabled
        $controls.btnRun.IsEnabled = $Enabled
        $controls.btnStop.IsEnabled = -not $Enabled
        
        if ($Enabled) {
            $controls.progressBar.Visibility = [System.Windows.Visibility]::Collapsed
            $controls.progressBar.IsIndeterminate = $false
        } else {
            $controls.progressBar.Visibility = [System.Windows.Visibility]::Visible
            $controls.progressBar.IsIndeterminate = $true
        }
    })
}

function Get-ExitCodeMessage {
    param([int]$ExitCode)
    
    switch ($ExitCode) {
        0  { return "Success" }
        1  { return "General error" }
        20 { return "Pending reboot detected" }
        21 { return "Installer is busy" }
        22 { return "Office Click-to-Run is busy" }
        23 { return "Service restart failure" }
        default { return "Unknown exit code: $ExitCode" }
    }
}

# ================================
# CLEANUP EXECUTION
# ================================
function Start-CleanupOperation {
    # Disable controls
    Enable-Controls -Enabled $false
    Update-Status "Running cleanup..." "#3498DB"
    
    $script:StartTime = Get-Date
    $controls.txtSpaceReclaimed.Text = ""
    
    # Start timer for elapsed time updates
    $script:Timer = New-Object System.Windows.Threading.DispatcherTimer
    $script:Timer.Interval = [TimeSpan]::FromSeconds(1)
    $script:Timer.Add_Tick({ Update-ElapsedTime })
    $script:Timer.Start()
    
    Write-GuiLog "=== OS CLEANUP OPERATION STARTED ==="
    Write-GuiLog "Aggressive: $($controls.chkAggressive.IsChecked)"
    Write-GuiLog "Skip Recycle Bin: $($controls.chkSkipRecycleBin.IsChecked)"
    Write-GuiLog "Skip Preflight: $($controls.chkSkipPreflight.IsChecked)"
    Write-GuiLog "WhatIf Mode: $($controls.chkWhatIf.IsChecked)"
    Write-GuiLog "Installer Busy Minutes: $($controls.sliderInstallerMinutes.Value)"
    Write-GuiLog ""
    
    # Create temporary script file
    $tempScript = [System.IO.Path]::GetTempFileName() + ".ps1"
    
    try {
        # Write cleanup script to temp file
        Set-Content -Path $tempScript -Value $script:CleanupScriptContent -ErrorAction Stop
        
        # Build arguments
        $arguments = @()
        if ($controls.chkAggressive.IsChecked) { $arguments += "-Aggressive" }
        if ($controls.chkSkipRecycleBin.IsChecked) { $arguments += "-SkipRecycleBin" }
        if ($controls.chkSkipPreflight.IsChecked) { $arguments += "-SkipPreflight" }
        if ($controls.chkWhatIf.IsChecked) { $arguments += "-WhatIf" }
        $arguments += "-InstallerBusyMinutes $([int]$controls.sliderInstallerMinutes.Value)"
        $arguments += "-Silent"
        
        # Create runspace
        $script:RunspacePool = [runspacefactory]::CreateRunspacePool(1, 1)
        $script:RunspacePool.Open()
        
        $script:CleanupRunspace = [powershell]::Create()
        $script:CleanupRunspace.RunspacePool = $script:RunspacePool
        
        # Add script with Write-GuiLog function injection
        [void]$script:CleanupRunspace.AddScript({
            param($ScriptPath, $Args, $GuiLogFunc, $WindowObj)
            
            # Make Write-GuiLog available to cleanup script
            $script:WriteGuiLog = {
                param([string]$Message)
                try {
                    if ($WindowObj.Dispatcher.CheckAccess()) {
                        # Already on UI thread, call directly
                        & $GuiLogFunc $Message
                    }
                    else {
                        # On background thread, marshal to UI
                        $WindowObj.Dispatcher.Invoke([action]{
                            & $GuiLogFunc $Message
                        }, [System.Windows.Threading.DispatcherPriority]::Normal)
                    }
                }
                catch {
                    # Silently fail if GUI update fails
                }
            }
            

            
            $output = @{
                ExitCode = 0
                LogFile = $null
                Output = @()
            }
            
            try {
                # Execute cleanup script with dot-sourcing to share scope
                $result = . $ScriptPath @Args 2>&1
                $output.ExitCode = $LASTEXITCODE
                $output.Output = $result
                
                # Find log file
                $logRoot = Join-Path $env:ProgramData "OSCleanup"
                if (Test-Path $logRoot) {
                    $latestLog = Get-ChildItem $logRoot -Filter "OSCleanup_*.log" -ErrorAction SilentlyContinue |
                        Sort-Object LastWriteTime -Descending |
                        Select-Object -First 1
                    
                    if ($latestLog) {
                        $output.LogFile = $latestLog.FullName
                    }
                }
            }
            catch {
                $output.ExitCode = 1
                $output.Output = @("ERROR: $_")
            }
            
            return $output
        })
        
        [void]$script:CleanupRunspace.AddArgument($tempScript)
        [void]$script:CleanupRunspace.AddArgument($arguments)
        [void]$script:CleanupRunspace.AddArgument(${function:Write-GuiLog})
        [void]$script:CleanupRunspace.AddArgument($window)
        
        # Start async
        $handle = $script:CleanupRunspace.BeginInvoke()
        
        # Monitor completion and pump UI messages
        $monitorTimer = New-Object System.Windows.Threading.DispatcherTimer
        $monitorTimer.Interval = [TimeSpan]::FromMilliseconds(100)
        
        $monitorTimer.Add_Tick({
            if ($handle.IsCompleted) {
                $monitorTimer.Stop()
                
                try {
                    $result = $script:CleanupRunspace.EndInvoke($handle)
                    
                    # Stop elapsed timer
                    if ($script:Timer) {
                        $script:Timer.Stop()
                    }
                    
                    # Parse log file for results
                    if ($result.LogFile -and (Test-Path $result.LogFile)) {
                        $script:LogPath = $result.LogFile
                        
                        # Read and display log
                        $logContent = Get-Content $result.LogFile -Raw -ErrorAction SilentlyContinue
                        if ($logContent) {
                            Write-GuiLog ""
                            Write-GuiLog "=== CLEANUP LOG ==="
                            Write-GuiLog $logContent
                        }
                        
                        # Extract space reclaimed
                        if ($logContent -match "Space reclaimed:\s*(.+)") {
                            $spaceReclaimed = $matches[1].Trim()
                            $window.Dispatcher.Invoke([action]{
                                $controls.txtSpaceReclaimed.Text = "💾 Reclaimed: $spaceReclaimed"
                            })
                        }
                    }
                    
                    # Handle exit code
                    $exitCode = $result.ExitCode
                    $exitMessage = Get-ExitCodeMessage -ExitCode $exitCode
                    
                    if ($exitCode -eq 0) {
                        Write-GuiLog ""
                        Write-GuiLog "✓ CLEANUP COMPLETED SUCCESSFULLY" -Color "#2ECC71"
                        Update-Status "Completed: $exitMessage" "#2ECC71"
                        
                        [System.Windows.MessageBox]::Show(
                            "Cleanup completed successfully!`n`nExit Code: $exitCode`nStatus: $exitMessage",
                            "Success",
                            [System.Windows.MessageBoxButton]::OK,
                            [System.Windows.MessageBoxImage]::Information
                        )
                    }
                    elseif ($exitCode -ge 20 -and $exitCode -le 23) {
                        Write-GuiLog ""
                        Write-GuiLog "⚠ PREFLIGHT CHECK FAILED" -Color "#E67E22"
                        Write-GuiLog "Exit Code: $exitCode - $exitMessage" -Color "#E67E22"
                        Update-Status "Preflight failed: $exitMessage" "#E67E22"
                        
                        [System.Windows.MessageBox]::Show(
                            "Preflight check failed.`n`nExit Code: $exitCode`nReason: $exitMessage`n`nPlease address the issue and try again, or use 'Skip Preflight' to force cleanup.",
                            "Preflight Failed",
                            [System.Windows.MessageBoxButton]::OK,
                            [System.Windows.MessageBoxImage]::Warning
                        )
                    }
                    else {
                        Write-GuiLog ""
                        Write-GuiLog "✗ CLEANUP FAILED" -Color "#E74C3C"
                        Write-GuiLog "Exit Code: $exitCode - $exitMessage" -Color "#E74C3C"
                        Update-Status "Failed: $exitMessage" "#E74C3C"
                        
                        [System.Windows.MessageBox]::Show(
                            "Cleanup operation failed.`n`nExit Code: $exitCode`nStatus: $exitMessage`n`nCheck the log for details.",
                            "Operation Failed",
                            [System.Windows.MessageBoxButton]::OK,
                            [System.Windows.MessageBoxImage]::Error
                        )
                    }
                }
                catch {
                    Write-GuiLog ""
                    Write-GuiLog "✗ ERROR: $_" -Color "#E74C3C"
                    Update-Status "Error occurred" "#E74C3C"
                    
                    [System.Windows.MessageBox]::Show(
                        "An error occurred during cleanup.`n`nError: $_",
                        "Error",
                        [System.Windows.MessageBoxButton]::OK,
                        [System.Windows.MessageBoxImage]::Error
                    )
                }
                finally {
                    # Cleanup
                    if ($script:CleanupRunspace) {
                        $script:CleanupRunspace.Dispose()
                        $script:CleanupRunspace = $null
                    }
                    if ($script:RunspacePool) {
                        $script:RunspacePool.Close()
                        $script:RunspacePool.Dispose()
                        $script:RunspacePool = $null
                    }
                    
                    # Remove temp script
                    if (Test-Path $tempScript) {
                        Remove-Item $tempScript -Force -ErrorAction SilentlyContinue
                    }
                    
                    Enable-Controls -Enabled $true
                }
            }
        })
        
        $monitorTimer.Start()
    }
    catch {
        Write-GuiLog "✗ Failed to start cleanup: $_" -Color "#E74C3C"
        Update-Status "Failed to start" "#E74C3C"
        Enable-Controls -Enabled $true
        
        if ($script:Timer) {
            $script:Timer.Stop()
        }
        
        if (Test-Path $tempScript) {
            Remove-Item $tempScript -Force -ErrorAction SilentlyContinue
        }
    }
}

function Stop-CleanupOperation {
    Write-GuiLog "⏹ Stopping cleanup operation..."
    Update-Status "Stopping..." "#E67E22"
    
    try {
        if ($script:CleanupRunspace) {
            $script:CleanupRunspace.Stop()
        }
        if ($script:RunspacePool) {
            $script:RunspacePool.Close()
            $script:RunspacePool.Dispose()
        }
    }
    catch {
        Write-GuiLog "Error stopping operation: $_"
    }
    finally {
        $script:CleanupRunspace = $null
        $script:RunspacePool = $null
        
        if ($script:Timer) {
            $script:Timer.Stop()
        }
        
        Enable-Controls -Enabled $true
        Update-Status "Stopped" "#E67E22"
        Write-GuiLog "Operation stopped by user"
    }
}

# ================================
# EVENT HANDLERS
# ================================

# Slider value changed
$controls.sliderInstallerMinutes.Add_ValueChanged({
    $controls.txtInstallerMinutes.Text = [int]$controls.sliderInstallerMinutes.Value
})

# Clear log button
$controls.btnClearLog.Add_Click({
    $controls.txtLog.Clear()
    Write-GuiLog "Log cleared"
})

# Run button
$controls.btnRun.Add_Click({
    $result = [System.Windows.MessageBox]::Show(
        "Are you sure you want to run the cleanup operation?",
        "Confirm Cleanup",
        [System.Windows.MessageBoxButton]::YesNo,
        [System.Windows.MessageBoxImage]::Question
    )
    
    if ($result -eq [System.Windows.MessageBoxResult]::Yes) {
        Start-CleanupOperation
    }
})

# Stop button
$controls.btnStop.Add_Click({
    Stop-CleanupOperation
})

# Open log file button
$controls.btnOpenLog.Add_Click({
    if ($script:LogPath -and (Test-Path $script:LogPath)) {
        Start-Process notepad.exe -ArgumentList $script:LogPath
    }
    else {
        $logRoot = Join-Path $env:ProgramData "OSCleanup"
        if (Test-Path $logRoot) {
            Start-Process explorer.exe -ArgumentList $logRoot
        }
        else {
            [System.Windows.MessageBox]::Show(
                "No log file available yet.`n`nLogs will be created in:`n$logRoot",
                "No Log File",
                [System.Windows.MessageBoxButton]::OK,
                [System.Windows.MessageBoxImage]::Information
            )
        }
    }
})

# Window closing
$window.Add_Closing({
    if ($script:CleanupRunspace -or $script:RunspacePool) {
        $result = [System.Windows.MessageBox]::Show(
            "Cleanup operation is still running. Are you sure you want to exit?",
            "Confirm Exit",
            [System.Windows.MessageBoxButton]::YesNo,
            [System.Windows.MessageBoxImage]::Warning
        )
        
        if ($result -eq [System.Windows.MessageBoxResult]::No) {
            $_.Cancel = $true
            return
        }
        
        # Force stop
        Stop-CleanupOperation
    }
    
    if ($script:Timer) {
        $script:Timer.Stop()
    }
})

# ================================
# INITIALIZATION
# ================================
Write-GuiLog "OS Cleanup Utility initialized"
Write-GuiLog "Running as: $env:USERNAME"
Write-GuiLog "Computer: $env:COMPUTERNAME"
Write-GuiLog "Ready to begin cleanup operation"
Write-GuiLog ""

# ================================
# SHOW WINDOW
# ================================
[void]$window.ShowDialog()
