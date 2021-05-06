import inspect
import functools
import types

from aiohttp import web


def is_handler_authentication_exempt(handler):
    """Return True if the endpoint handler is authentication exempt."""
    try:
        is_unauthenticated = handler.__caldera_unauthenticated__
    except AttributeError:
        is_unauthenticated = False
    return is_unauthenticated


def _wrap_async_method(method: types.MethodType):
    """Wrap the input bound async method in an async function."""
    async def wrapper(*args, **kwargs):
        return await method(*args, **kwargs)
    return functools.wraps(method)(wrapper)


def _wrap_sync_method(method: types.MethodType):
    """Wrap the input bound method in an async function."""
    def wrapper(*args, **kwargs):
        return method(*args, **kwargs)
    return functools.wraps(method)(wrapper)


def _wrap_method(method: types.MethodType):
    if inspect.iscoroutinefunction(method):
        return _wrap_async_method(method)
    return _wrap_method(method)


def is_handler_authorization_exempt(handler):
    if is_handler_authentication_exempt(handler):
        return True
    return len(get_required_permissions(handler)) == 0


def authorization_required(*permissions):
    def wrapper(handler):
        if inspect.ismethod(handler):
            handler = _wrap_method(handler)

        handler.__caldera_required_permissions__ = tuple(permissions)
        return handler
    return wrapper


def get_required_permissions(handler):
    try:
        required_permissions = handler.__caldera_required_permissions__
    except AttributeError:
        required_permissions = ()
    return required_permissions


def authorization_middleware_factory(auth_svc):
    @web.middleware
    async def authorization_middleware(request, handler):
        if is_handler_authentication_exempt(handler):
            return await handler(request)
        if is_handler_authorization_exempt(handler):
            return await handler(request)
        if await auth_svc.is_request_authorized(request, get_required_permissions(handler)):
            return await handler(request)
        raise web.HTTPForbidden()
    return authorization_middleware


def authentication_exempt(handler):
    """Mark the endpoint handler as not requiring authentication.

    Note:
        This only applies when the authentication_required_middleware is
        being used.
    """
    # Can't set attributes directly on a bound method so we need to
    # wrap it in a function that we can mark it as unauthenticated
    if inspect.ismethod(handler):
        handler = _wrap_method(handler)

    handler.__caldera_unauthenticated__ = True
    return handler


def authentication_required_middleware_factory(auth_svc):
    """Enforce authentication on every endpoint within an web application.

    Note:
        Any endpoint handler can opt-out of authentication using the
        @authentication_exempt decorator.
    """
    @web.middleware
    async def authentication_required_middleware(request, handler):
        if is_handler_authentication_exempt(handler):
            return await handler(request)
        if not await auth_svc.is_request_authenticated(request):
            raise web.HTTPUnauthorized()
        return await handler(request)
    return authentication_required_middleware
