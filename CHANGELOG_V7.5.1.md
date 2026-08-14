# V7.5.1 Hotfix

- Fixed public Red Card PIN-unlock display.
- Red Card image/PDF requests now use a per-view session token created before redirect.
- Added authorized Admin/Chief/Officer access to the protected public Red Card file route.
- Allowed same-origin PDF embedding for the protected Red Card viewer while retaining the global DENY frame policy elsewhere.
- Refreshing/reopening the public member profile clears the Red Card per-view token.
- Corrected application VERSION to 7.5.1.
