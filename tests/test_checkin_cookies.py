from http.cookies import SimpleCookie

import httpx
import pytest

import checkin
from utils.config import AccountConfig, AppConfig, ProviderConfig


@pytest.mark.asyncio
@pytest.mark.parametrize('cookie_format', ['dict', 'header'])
async def test_check_in_replaces_stale_waf_cookies_and_preserves_session(monkeypatch, cookie_format):
	user_cookies = {
		'session': 'account-session',
		'acw_tc': 'stale-acw',
		'cdn_sec_tc': 'stale-cdn',
		'acw_sc__v2': 'stale-challenge',
	}
	fresh_waf_cookies = {
		'acw_tc': 'fresh-acw',
		'cdn_sec_tc': 'fresh-cdn',
		'acw_sc__v2': 'fresh-challenge',
	}
	provider = ProviderConfig(
		name='anyrouter',
		domain='https://checkin.example',
		bypass_method='waf_cookies',
		waf_cookie_names=list(fresh_waf_cookies),
	)

	async def get_fresh_waf_cookies(*args, **kwargs):
		return fresh_waf_cookies.copy()

	requests = []

	def handle_request(request):
		requests.append(request)
		cookies = SimpleCookie()
		cookies.load(request.headers['cookie'])
		assert cookies['session'].value == 'account-session'
		assert request.headers['new-api-user'] == '12345'
		if any(cookies[name].value != value for name, value in fresh_waf_cookies.items()):
			return httpx.Response(200, text='<html>WAF challenge</html>')
		if request.method == 'POST':
			assert request.url.path == '/api/user/sign_in'
			return httpx.Response(200, json={'success': True})
		assert request.url.path == '/api/user/self'
		return httpx.Response(200, json={'success': True, 'data': {'quota': 500000, 'used_quota': 0}})

	original_client = httpx.Client

	def make_client(**kwargs):
		return original_client(transport=httpx.MockTransport(handle_request), **kwargs)

	monkeypatch.setattr(checkin, 'get_waf_cookies_with_browser', get_fresh_waf_cookies)
	monkeypatch.setattr(checkin.httpx, 'Client', make_client)
	configured_cookies = (
		user_cookies
		if cookie_format == 'dict'
		else '; '.join(f'{name}={value}' for name, value in user_cookies.items())
	)
	account = AccountConfig(cookies=configured_cookies, api_user='12345')

	success, before, after = await checkin.check_in_account(account, 0, AppConfig(providers={'anyrouter': provider}))

	assert success is True
	assert before['success'] is True
	assert after['success'] is True
	assert len(requests) == 3
	assert user_cookies['acw_tc'] == 'stale-acw'
