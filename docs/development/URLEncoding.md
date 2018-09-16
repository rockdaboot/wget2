This document tries to describe what the correct handling for charset encoding/decoding and percent encoding/decoding (escaping) should be. 'URL' is used in general for URI/IRI/URL here.

### Encoding/Decoding
We basically need 4 different settings for character encoding.

1. The encoding of the filename(s) that we want to generate (e.g. utf-8). We have --local-encoding for this. An should have --filename-encoding in the future.
2. The encoding of the URL(s) given on the command line (e.g. gp2312). We have --local-encoding for this.
3. The encoding of the content of --input-file (e.g. iso-8859-15). We have --remote-encoding for this. Wget2 already has --input-encoding.
4. The encoding of the content of downloaded HTML (e.g. cp1252). We have --remote-encoding for this. In fact, this should only be a default for cases where we can't determine the encoding otherwise (normally we can).

These 4 encodings may all be needed for one single invocation of Wget. Any combination should be allowed. This is why we need 4 different command line options.

[How to encode HTTP Get strings](http://stackoverflow.com/questions/1549213/whats-the-correct-encoding-of-http-get-request-strings)

### Escaping/Unescaping
URLs may be partially %-encoded (escaped). We should only support single-escaped strings.
URLs should first be parsed into their parts, the host part unescaped and converted to UTF-8 + punycode (if needed), the path unescaped and converted to UTF-8. Query and fragment ? Stay as they are or converted to UTF-8 ? That depends on the processing script on the server side, I guess.

### Putting together the GET string
/ + escaped UTF-8 path + ? + escaped query + # + escaped fragment

### Generating the filename
If host is part of the filename/path: convert host to filename encoding, if not possible use punycode.
Convert the remaining part of the filename into filename encoding if possible. Percent-encode all special characters (not printable or not allowed for the file system).

### Document encoding
 * about encoding see http://nikitathespider.com/articles/EncodingDivination.html
 * about GET encoding see http://stackoverflow.com/questions/1549213/whats-the-correct-encoding-of-http-get-request-strings
 * [RFC 3986 URI generic syntax](http://www.rfc-base.org/rfc-3986.html)
 * [W3Schools URL Encoding] http://www.w3schools.com/tags/ref_urlencode.asp
 * [W3Schools Charset] http://www.w3schools.com/tags/ref_charactersets.asp
 * [W3Schools HTML Entities] http://www.w3schools.com/html/html_entities.asp
