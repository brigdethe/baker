var utm = function() {
    var params = new URLSearchParams(window.location.search);
    var keys = ['utm_campaign', 'utm_source', 'utm_medium', 'utm_content', 'utm_term'];

    var set_cookie = function(name, value, days) {
        var d = new Date();
        d.setTime(d.getTime() + (24*60*60*1000) * days);

        document.cookie = name + '=' + value + ';expires=' + d.toUTCString() + ';path=/';
    }

    var get_cookie = function(name) {
        var match = document.cookie.match(new RegExp('(^| )' + name + '=([^;]+)'));
        if (match) return match[2];
    }

    var is_referrer_organic = function(referrer) {
        var organic_sources = [
            'google',
            'bing',
            'yahoo',
            'ask',
            'baidu',
            'yandex',
            'naver'
        ];

        for (x in organic_sources) {
            if (referrer.indexOf(organic_sources[x]) >= 0) {
                return true;
            }
        }

        return false;
    }

    var trim_referrer = function(referrer) {
        var trim_sources = [
            'www.',
            'r.search.',
            'ca.search'
        ];

        for (x in trim_sources) {
            referrer = referrer.replace(trim_sources[x], '');
        }

        return referrer;

    }

    for (x in keys) {
        if (params.get(keys[x]) != undefined) {
            set_cookie(keys[x], params.get(keys[x]), 30);
        }
    } 

    if (get_cookie('utm_source') == null) {
        var source = 'none';
        if (document.referrer != null && document.referrer != '') {
            var url = new URL(document.referrer);
            source = trim_referrer(url.hostname);
        }

        set_cookie('utm_source', source, 30);
    }

    if (get_cookie('utm_medium') == null) {
        var medium = 'direct';
        if (document.referrer != null && document.referrer != '') {
            var url = new URL(document.referrer);
            if (is_referrer_organic(url.hostname)) {
                medium = 'organic';
            } else {
                medium = 'referral';
            }
        }

        set_cookie('utm_medium', medium, 30);
    }

    if (get_cookie('utm_referrer') == null) {
        if (document.referrer != null && document.referrer != '') {
            set_cookie('utm_referrer', document.referrer, 30);
        }
    }

    if (get_cookie('utm_landing') == null) {
        set_cookie('utm_landing', location.href, 30);
    }
}();