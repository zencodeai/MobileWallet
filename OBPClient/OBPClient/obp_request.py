import requests

from OBPClient import OBPClientRoot


class OBPRequest(OBPClientRoot):

	def __init__(self, api_root: str, api_version: str, host_prefix: str, host_name: str):
		# Class constructor
		super().__init__()
		self._api_root = api_root
		self._api_version = api_version
		self._host_prefix = host_prefix
		self._host_name = host_name

	def _get_url(self, endpoint: str) -> str:
		# Get URL from configuration and parameters
		return '{}{}{}'.format(self._host_prefix, self._host_name, endpoint)

	def _get_api_url(self, endpoint: str) -> str:
		# Get URL from configuration and parameters
		return self._get_url("/{}/{}{}".format(self._api_root, self._api_version, endpoint))

	@classmethod
	def _get_api_headers(cls, auth_headers: dict) -> dict:
		# Add authentication headers to API request headers
		api_headers = {'Accept': 'application/json'}
		api_headers.update(auth_headers)
		return api_headers

	@classmethod
	def assert_satus_code(cls, rsp: requests.Response, value: list[int]):
		if rsp.status_code not in value:
			raise Exception('Request failed {} : {}'.format(rsp.status_code, rsp.text))

	def post(self, endpoint: str, headers: dict) -> requests.Response:
		# Post request
		return requests.post(self._get_url(endpoint), headers=headers)

	def api_get(self, endpoint: str, auth_headers: dict) -> requests.Response:
		# API GET request
		api_headers = self._get_api_headers(auth_headers)
		return requests.get(self._get_api_url(endpoint), headers=api_headers)

	def api_post(self, endpoint: str, auth_headers: dict, payload: dict) -> requests.Response:
		# API POST request
		api_headers = self._get_api_headers(auth_headers)
		return requests.post(self._get_api_url(endpoint), headers=api_headers, json=payload)

	def api_put(self, endpoint: str, auth_headers: dict, payload: dict) -> requests.Response:
		# API PUT request
		api_headers = self._get_api_headers(auth_headers)
		return requests.put(self._get_api_url(endpoint), headers=api_headers, json=payload)

	def api_delete(self, endpoint: str, auth_headers: dict) -> requests.Response:
		# API DELETE request
		api_headers = self._get_api_headers(auth_headers)
		return requests.delete(self._get_api_url(endpoint), headers=api_headers)

	def api_post_abs(self, endpoint: str, auth_headers: dict, payload: dict) -> requests.Response:
		# API POST request
		api_headers = self._get_api_headers(auth_headers)
		return requests.post(endpoint, headers=api_headers, json=payload)
