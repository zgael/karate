package com.intuit.karate.http;

import io.netty.handler.codec.DateFormatter;
import io.netty.handler.codec.http.cookie.Cookie;
import io.netty.handler.codec.http.cookie.CookieUtil;
import io.netty.handler.codec.http.cookie.DefaultCookie;
import io.netty.util.internal.ObjectUtil;

import java.util.Date;

public class KarateCookie {

    public String encode(Cookie cookie) {
        String name = ((Cookie) ObjectUtil.checkNotNull(cookie, "cookie")).name();
        String value = cookie.value() != null ? cookie.value() : "";
        this.validateCookie(name, value);
        StringBuilder buf = CookieUtil.stringBuilder();
        if (cookie.wrap()) {
            CookieUtil.addQuoted(buf, name, value);
        } else {
            CookieUtil.add(buf, name, value);
        }

        if (cookie.maxAge() != -9223372036854775808L) {
            CookieUtil.add(buf, "Max-Age", cookie.maxAge());
            Date expires = new Date(cookie.maxAge() * 1000L + System.currentTimeMillis());
            buf.append("Expires");
            buf.append('=');
            DateFormatter.append(expires, buf);
            buf.append(';');
            buf.append(' ');
        }

        if (cookie.path() != null) {
            CookieUtil.add(buf, "Path", cookie.path());
        }

        if (cookie.domain() != null) {
            CookieUtil.add(buf, "Domain", cookie.domain());
        }

        if (cookie.isSecure()) {
            CookieUtil.add(buf, "Secure");
        }

        if (cookie.isHttpOnly()) {
            CookieUtil.add(buf, "HTTPOnly");
        }

        if (cookie instanceof DefaultCookie) {
            DefaultCookie c = (DefaultCookie) cookie;
            if (c.sameSite() != null) {
                CookieUtil.add(buf, "SameSite", c.sameSite().name());
            }
        }

        return CookieUtil.stripTrailingSeparator(buf);
    }
}
}
