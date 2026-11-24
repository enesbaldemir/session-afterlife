# Privacy policy

Session Afterlife does not collect, store on any server, sell or share any data.

## What the extension reads

Only for the sites in scope (localhost and 127.0.0.1 by default, plus the sites you add and grant access to):

- the cookies that apply to the request you pick, including `HttpOnly` cookies;
- the headers of requests your tabs send to that site, including `Cookie` and `Authorization`;
- the responses to the requests the extension replays.

## Where it is kept

Session values, captured requests and results are kept in `chrome.storage.session`, which lives in the browser's memory and is cleared when the browser closes. Preferences (the scope list, automatic or manual mode, the selected test and timeout options) are kept in `chrome.storage.local`. Nothing leaves your browser. The extension makes network requests only to sites in scope.

## Showing values

The panel can show and copy cookie values and tokens of the recorded session when you click **Show** or **Copy**. They are masked otherwise.

## Reports

Exported reports contain verdicts, cookie names and lifetimes. They never contain cookie values, tokens or the marker text.

## Contact

Open an issue in this repository.
