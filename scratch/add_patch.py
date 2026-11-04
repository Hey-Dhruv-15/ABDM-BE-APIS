with open('app/abdm/client.py', 'rb') as f:
    data = f.read()

target = b'''    async def post(
        self,
        path: str,
        body: Dict[str, Any],
        include_participant_header: bool = True,
        participant_id: str | None = None,
        participant_type: str | None = None,
        base_url: str | None = None,
        extra_headers: Dict[str, str] | None = None,
        include_cm_header: bool = True,
        include_auth_header: bool = True,
    ) -> Any:
        """POST JSON to ABDM with automatic token refresh on 401."""
        return await self._request(
            method="POST",
            path=path,
            json_body=body,
            include_participant_header=include_participant_header,
            participant_id=participant_id,
            participant_type=participant_type,
            base_url=base_url,
            extra_headers=extra_headers,
            include_cm_header=include_cm_header,
            include_auth_header=include_auth_header,
        )'''

patch_code = b'''

    async def patch(
        self,
        path: str,
        body: Dict[str, Any] | None = None,
        include_participant_header: bool = True,
        participant_id: str | None = None,
        participant_type: str | None = None,
        base_url: str | None = None,
        extra_headers: Dict[str, str] | None = None,
        include_cm_header: bool = True,
        include_auth_header: bool = True,
    ) -> Any:
        """PATCH JSON to ABDM with automatic token refresh on 401."""
        return await self._request(
            method="PATCH",
            path=path,
            json_body=body,
            include_participant_header=include_participant_header,
            participant_id=participant_id,
            participant_type=participant_type,
            base_url=base_url,
            extra_headers=extra_headers,
            include_cm_header=include_cm_header,
            include_auth_header=include_auth_header,
        )

    async def put(
        self,
        path: str,
        body: Dict[str, Any] | None = None,
        include_participant_header: bool = True,
        participant_id: str | None = None,
        participant_type: str | None = None,
        base_url: str | None = None,
        extra_headers: Dict[str, str] | None = None,
        include_cm_header: bool = True,
        include_auth_header: bool = True,
    ) -> Any:
        """PUT JSON to ABDM with automatic token refresh on 401."""
        return await self._request(
            method="PUT",
            path=path,
            json_body=body,
            include_participant_header=include_participant_header,
            participant_id=participant_id,
            participant_type=participant_type,
            base_url=base_url,
            extra_headers=extra_headers,
            include_cm_header=include_cm_header,
            include_auth_header=include_auth_header,
        )'''

if b'\r\n' in data:
    target = target.replace(b'\n', b'\r\n')
    patch_code = patch_code.replace(b'\n', b'\r\n')
else:
    target = target.replace(b'\r\n', b'\n')
    patch_code = patch_code.replace(b'\r\n', b'\n')

assert target in data, 'Target not found in app/abdm/client.py'
new_data = data.replace(target, target + patch_code, 1)
with open('app/abdm/client.py', 'wb') as f:
    f.write(new_data)
print('SUCCESS')

