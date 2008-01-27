# ===========================================================================
# Copyright Everitz Consulting.  Not for redistribution.
# ===========================================================================
package MT::Plugin::HTTPBL;

use strict;

use base qw( MT::Plugin );

use MT;
use MT::JunkFilter qw(ABSTAIN);

# plugin registration

my $plugin = MT::Plugin::HTTPBL->new({
    id             => 'http:BL',
    key            => 'httpbl',
    name           => 'MT-http:BL',
    description    => q(<__trans phrase="Additional anti-spam measures for your Movable Type installation.">),
    author_name    => 'Everitz Consulting',
    author_link    => 'http://everitz.com/',
    plugin_link    => 'http://everitz.com/mt/httpbl/index.php',
    doc_link       => 'http://everitz.com/mt/httpbl/index.php#install',
#    l10n_class     => 'HTTPBL::L10N',
    version        => '0.0.2',
#
# settings
#
    blog_config_template   => \&settings_template_blog,
    system_config_template => \&settings_template_system,
    settings               => new MT::PluginSettings([
        ['httpbl_age',           { Default => 255 }],
        ['httpbl_age_mode',      { Default => 2 }],
        ['httpbl_age_weight',    { Default => 1 }],
        ['httpbl_threat',        { Default => 1 }],
        ['httpbl_threat_mode',   { Default => 2 }],
        ['httpbl_threat_weight', { Default => 1 }],
        ['httpbl_type_1',        { Default => 1 }],
        ['httpbl_type_2',        { Default => 1 }],
        ['httpbl_type_3',        { Default => 1 }],
        ['httpbl_type_mode',     { Default => 2 }],
        ['httpbl_type_weight',   { Default => 1 }],
        ['httpbl_key',           { Default => '',  Scope => 'system' }],
    ]),
});
MT->add_plugin($plugin);

MT->register_junk_filter({name => 'httpBL Age', code => \&httpbl_age});
MT->register_junk_filter({name => 'httpBL Threat', code => \&httpbl_threat});
MT->register_junk_filter({name => 'httpBL Type', code => \&httpbl_type});

sub apply_default_settings {
    my $plugin = shift;
    my ($data, $scope) = @_;
    if ($scope ne 'system') {
        my $sys = $plugin->get_config_obj('system');
        my $sysdata = $sys->data();
        if ($plugin->{settings} && $sysdata) {
            foreach (keys %$sysdata) {
                $data->{$_} = $sysdata->{$_} if !exists $data->{$_};
            }
        }
    } else {
        $plugin->SUPER::apply_default_settings(@_);
    }
}

sub httpbl_age {
    my $obj = shift;
    my $key = is_valid_key($obj) or return ABSTAIN;
    my $hbo = is_valid_obj($obj) or return ABSTAIN;
    my $config = $plugin->get_config_hash('blog:'.$obj->blog_id);
    my $threshold = $config->{httpbl_age};
    my ($a, $b, $c, $d) = split /\./, $hbo;
    if ($b <= $threshold) {
        my $log = $plugin->translate("Age Threshold Exceeded ([_1])", $b);
        if ($config->{httpbl_mode} == 2) {
            $obj->moderate;
            return (0, $log);
        } else {
            return (-1 * (int($config->{httpbl_age_weight}) || 1), $log);
        }
    } else {
      	return ABSTAIN;
    }
}

sub httpbl_threat {
    my $obj = shift;
    my $key = is_valid_key($obj) or return ABSTAIN;
    my $hbo = is_valid_obj($obj) or return ABSTAIN;
    my $config = $plugin->get_config_hash('blog:'.$obj->blog_id);
    my $threshold = $config->{httpbl_threat};
    my ($a, $b, $c, $d) = split /\./, $hbo;
    if ($c >= $threshold) {
        my $log = $plugin->translate("Threat Threshold Exceeded ([_1])", $c);
        if ($config->{httpbl_mode} == 2) {
            $obj->moderate;
            return (0, $log);
        } else {
            return (-1 * (int($config->{httpbl_threat_weight}) || 1), $log);
        }
    } else {
        return ABSTAIN;
    }
}

sub httpbl_type {
    my $obj = shift;
    my $key = is_valid_key($obj) or return ABSTAIN;
    my $hbo = is_valid_obj($obj) or return ABSTAIN;
    my $config = $plugin->get_config_hash('blog:'.$obj->blog_id);
    my ($a, $b, $c, $d) = split /\./, $hbo;
    if ($d) {
        my $threshold = 0;
        if ($config->{httpbl_type_1}) {
            $threshold++ if ($d == 1 || $d == 3 || $d == 5 || $d == 7);
        }
        if ($config->{httpbl_type_2}) {
            $threshold++ if ($d == 2 || $d == 3 || $d == 6 || $d == 7);
        }
        if ($config->{httpbl_type_3}) {
            $threshold++ if ($d == 4 || $d == 5 || $d == 6 || $d == 7);
        }
        my %types = (
            0, 'Search Engine',
            1, 'Suspicious',
            2, 'Harvester',
            3, 'Suspicious & Harvester',
            4, 'Comment Spammer',
            5, 'Suspicious & Comment Spammer',
            6, 'Harvester & Comment Spammer',
            7, 'Suspicious & Harvester & Comment Spammer',
        );
        if ($threshold) {
            my $log = $plugin->translate("Type Threshold Exceeded ([_1])", $types{$d});
            if ($config->{httpbl_mode} == 2) {
                $obj->moderate;
                return (0, $log);
            } else {
                return (-1 * (int($config->{httpbl_type_weight}) || 1), $log);
            }
        }
    } else {
      	return ABSTAIN;
    }
}

sub is_valid_key {
    my $obj = shift;
    my $r = MT->request;
    unless ($r->stash('MT::Plugin::HTTPBL::httpbl_key')) {
        my $key = $plugin->get_config_value('httpbl_key') || return;
        $r->stash('MT::Plugin::HTTPBL::httpbl_key', $key);
    }
    $r->stash('MT::Plugin::HTTPBL::httpbl_key');
}

sub is_valid_obj {
    my $obj = shift;
    return (ABSTAIN) unless ($obj->ip);
    my $r = MT->request;
    unless ($r->stash('MT::Plugin::HTTPBL::httpbl_obj'.$obj->id)) {
        my $config = $plugin->get_config_hash('blog:'.$obj->blog_id);
        my $key = is_valid_key() or return ABSTAIN;
        my $remote_ip = $obj->ip;
        my $service = 'dnsbl.httpbl.org';
        $remote_ip = '127.40.1.1';
        my $mt = MT->instance;
        $mt->log("ip: $remote_ip");
        my ($a, $b, $c, $d) = split /\./, $remote_ip;
        require Net::DNS;
        my $res = Net::DNS::Resolver->new;
        my $add = "$key.$d.$c.$b.$a.$service.";
        if (my $search = $res->search($add)) {
            foreach my $rr ($search->answer) {
                next unless ($rr->type eq 'A');
                $r->stash('MT::Plugin::HTTPBL::httpbl_obj'.$obj->id, $rr->address);
            }
        } else {
            return ABSTAIN;
        }
    }
    $r->stash('MT::Plugin::HTTPBL::httpbl_obj'.$obj->id);
}

sub settings_template_blog {
    my ($plugin, $param) = @_;
    my $app = MT->instance;
    my $static = MT->app->static_path.'images';
    my $blog_id = $app->param('blog_id');
    return <<TMPL;
<script language="JavaScript">
    <!--
        function hide_and_seek () {
            var e;
            e = document.getElementById('httpbl_age_mode-prefs');
            if (document.getElementById('httpbl_age_mode_0').checked) { e.style.display = "none"; } else { e.style.display = "block"; }
            e = document.getElementById('httpbl_threat_mode-prefs');
            if (document.getElementById('httpbl_threat_mode_0').checked) { e.style.display = "none"; } else { e.style.display = "block"; }
            e = document.getElementById('httpbl_type_mode-prefs');
            if (document.getElementById('httpbl_type_mode_0').checked) { e.style.display = "none"; } else { e.style.display = "block"; }
        }
    //-->
</script>
<fieldset>
    <p><__trans phrase="The age threshold allows you to control the freshness of the data returned by the <strong>http:BL</strong> lookup.  If the age of the last activity is older than the value you specify here, this test will be ignored.  Currently, the age ranges from 0-255.  To disable entirely, turn off or set to 0.  To catch anything in the system, set this value to 255."></p>
    <mtapp:setting
        id="httpbl_age_mode"
        label="<__trans phrase="Age Action">"
        hint=""
        show_hint="0">
        <ul>
            <li><input onclick="toggleSubPrefs(this); hide_and_seek()" type="radio" id="httpbl_age_mode_0" name="httpbl_age_mode" value="0" <mt:unless name="httpbl_age_mode">checked="checked"</mt:unless> /> <__trans phrase="Off"></li>
            <li><input onclick="toggleSubPrefs(this); hide_and_seek()" type="radio" id="httpbl_age_mode_2" name="httpbl_age_mode" value="2" <mt:if name="httpbl_age_mode_2">checked="checked"</mt:if> /> <__trans phrase="Moderate feedback from throttled records"></li>
            <li><input onclick="toggleSubPrefs(this); hide_and_seek()" type="radio" id="httpbl_age_mode_1" name="httpbl_age_mode" value="1" <mt:if name="httpbl_age_mode_1">checked="checked"</mt:if> /> <__trans phrase="Junk feedback from throttled records"> (<a href="javascript:void(0)" onclick="return toggleAdvancedPrefs(event,'httpbl_age_mode_1')"><__trans phrase="Adjust scoring"></a>)
                <span id="httpbl_age_mode_1-advanced" class="setting-advanced"><__trans phrase="Score weight:">
                    <a href="javascript:void(0)" class="spinner" onclick="return junkScoreNudge(-1, 'httpbl_age_weight')"><!-- <__trans phrase="Less"> --><img src="$static/decrease.gif" alt="<__trans phrase="Decrease">" width="12" height="8" /></a>
                    <input type="text" size="3" id="httpbl_age_weight" name="httpbl_age_weight" value="<mt:var name="httpbl_age_weight" escape="html">" />
                    <a href="javascript:void(0)" class="spinner" onclick="return junkScoreNudge(1,'httpbl_age_weight')"><img src="$static/increase.gif" alt="<__trans phrase="Increase">" width="12" height="8" /><!-- <__trans phrase="More"> --></a>
                </span>
            </li>
        </ul>
    </mtapp:setting>
    <div id="httpbl_age_mode-prefs" style="display: <mt:unless name="httpbl_age_mode">none<mt:else>block</mt:unless>;">
        <mtapp:setting
            id="httpbl_age"
            label="<__trans phrase="Age Threshold">">
            <p><input id="httpbl_age" name="httpbl_age" size="3" <mt:if name="httpbl_age">value="<mt:var name="httpbl_age">"</mt:if> /></p>
        </mtapp:setting>
    </div>
    <p><__trans phrase="The threat threshold allows you to dictate the threat level of the data returned by the <strong>http:BL</strong> lookup.  The threat score is based on a number of factors, such as the number of honey pots visited and the damage done during those visits.  If the threat score returned is lower than the value you specify here, this test will be ignored.  Currently, the threat ranges from 0-255.  To disable entirely, turn off or set to 0.  Setting to 255 will permit any threat levels through, so if you want to block even the smallest threats, set to 1, which will catch everything at that level and above."></p>
    <mtapp:setting
        id="httpbl_threat_mode"
        label="<__trans phrase="Threat Action">"
        hint=""
        show_hint="0">
        <ul>
            <li><input onclick="toggleSubPrefs(this); hide_and_seek()" type="radio" id="httpbl_threat_mode_0" name="httpbl_threat_mode" value="0" <mt:unless name="httpbl_threat_mode">checked="checked"</mt:unless> /> <__trans phrase="Off"></li>
            <li><input onclick="toggleSubPrefs(this); hide_and_seek()" type="radio" id="httpbl_threat_mode_2" name="httpbl_threat_mode" value="2" <mt:if name="httpbl_threat_mode_2">checked="checked"</mt:if> /> <__trans phrase="Moderate feedback from throttled records"></li>
            <li><input onclick="toggleSubPrefs(this); hide_and_seek()" type="radio" id="httpbl_threat_mode_1" name="httpbl_threat_mode" value="1" <mt:if name="httpbl_threat_mode_1">checked="checked"</mt:if> /> <__trans phrase="Junk feedback from throttled records"> (<a href="javascript:void(0)" onclick="return toggleAdvancedPrefs(event,'httpbl_threat_mode_1')"><__trans phrase="Adjust scoring"></a>)
                <span id="httpbl_threat_mode_1-advanced" class="setting-advanced"><__trans phrase="Score weight:">
                    <a href="javascript:void(0)" class="spinner" onclick="return junkScoreNudge(-1, 'httpbl_threat_weight')"><!-- <__trans phrase="Less"> --><img src="$static/decrease.gif" alt="<__trans phrase="Decrease">" width="12" height="8" /></a>
                    <input type="text" size="3" id="httpbl_threat_weight" name="httpbl_threat_weight" value="<mt:var name="httpbl_threat_weight" escape="html">" />
                    <a href="javascript:void(0)" class="spinner" onclick="return junkScoreNudge(1,'httpbl_threat_weight')"><img src="$static/increase.gif" alt="<__trans phrase="Increase">" width="12" height="8" /><!-- <__trans phrase="More"> --></a>
                </span>
            </li>
        </ul>
    </mtapp:setting>
    <div id="httpbl_threat_mode-prefs" style="display: <mt:unless name="httpbl_threat_mode">none<mt:else>block</mt:unless>;">
        <mtapp:setting
            id="httpbl_threat"
            label="<__trans phrase="Threat Threshold">">
            <p><input id="httpbl_threat" name="httpbl_threat" size="3" <mt:if name="httpbl_threat">value="<mt:var name="httpbl_threat">"</mt:if> /></p>
        </mtapp:setting>
    </div>
    <p><__trans phrase="The type threshold allows you to indicate the types of visitors that you will permit in the data returned by the <strong>http:BL</strong> lookup.  If the type matches the value you specify here, this test will be triggered.  Currently, there are three type types.  You may choose any or all of them."></p>
    <mtapp:setting
        id="httpbl_type_mode"
        label="<__trans phrase="Type Threshold">"
        hint=""
        show_hint="0">
        <ul>
            <li><input onclick="toggleSubPrefs(this); hide_and_seek()" type="radio" id="httpbl_type_mode_0" name="httpbl_type_mode" value="0" <mt:unless name="httpbl_type_mode">checked="checked"</mt:unless> /> <__trans phrase="Off"></li>
            <li><input onclick="toggleSubPrefs(this); hide_and_seek()" type="radio" id="httpbl_type_mode_2" name="httpbl_type_mode" value="2" <mt:if name="httpbl_type_mode_2">checked="checked"</mt:if> /> <__trans phrase="Moderate feedback from throttled records"></li>
            <li><input onclick="toggleSubPrefs(this); hide_and_seek()" type="radio" id="httpbl_type_mode_1" name="httpbl_type_mode" value="1" <mt:if name="httpbl_type_mode_1">checked="checked"</mt:if> /> <__trans phrase="Junk feedback from throttled records"> (<a href="javascript:void(0)" onclick="return toggleAdvancedPrefs(event,'httpbl_type_mode_1')"><__trans phrase="Adjust scoring"></a>)
                <span id="httpbl_type_mode_1-advanced" class="setting-advanced"><__trans phrase="Score weight:">
                    <a href="javascript:void(0)" class="spinner" onclick="return junkScoreNudge(-1, 'httpbl_type_weight')"><!-- <__trans phrase="Less"> --><img src="$static/decrease.gif" alt="<__trans phrase="Decrease">" width="12" height="8" /></a>
                    <input type="text" size="3" id="httpbl_threat_weight" name="httpbl_type_weight" value="<mt:var name="httpbl_type_weight" escape="html">" />
                    <a href="javascript:void(0)" class="spinner" onclick="return junkScoreNudge(1,'httpbl_type_weight')"><img src="$static/increase.gif" alt="<__trans phrase="Increase">" width="12" height="8" /><!-- <__trans phrase="More"> --></a>
                </span>
            </li>
        </ul>
    </mtapp:setting>
    <div id="httpbl_type_mode-prefs" style="display: <mt:unless name="httpbl_type_mode">none<mt:else>block</mt:unless>;">
        <mtapp:setting
            id="httpbl_type"
            label="<__trans phrase="Type Action">"
            hint=""
            show_hint="0">
            <ul>
                <li><input type="checkbox" name="httpbl_type_1" id="httpbl_type_1" value="1" <mt:if name="httpbl_type_1">checked="checked"</mt:if> /> <__trans phrase="Suspicious">
                <li><input type="checkbox" name="httpbl_type_2" id="httpbl_type_2" value="2" <mt:if name="httpbl_type_2">checked="checked"</mt:if> /> <__trans phrase="Harvester">
                <li><input type="checkbox" name="httpbl_type_3" id="httpbl_type_3" value="4" <mt:if name="httpbl_type_3">checked="checked"</mt:if> /> <__trans phrase="Comment Spammer">
            </ul>
        </mtapp:setting>
    </div>
</fieldset>
TMPL
}

sub settings_template_system {
    my ($plugin, $param) = @_;
    my $app = MT->instance;
    my $static = MT->app->static_path.'images';
    return <<TMPL;
<script language="JavaScript">
    <!--
        function hide_and_seek () {
            var e;
            e = document.getElementById('httpbl_age_mode-prefs');
            if (document.getElementById('httpbl_age_mode_0').checked) { e.style.display = "none"; } else { e.style.display = "block"; }
            e = document.getElementById('httpbl_threat_mode-prefs');
            if (document.getElementById('httpbl_threat_mode_0').checked) { e.style.display = "none"; } else { e.style.display = "block"; }
            e = document.getElementById('httpbl_type_mode-prefs');
            if (document.getElementById('httpbl_type_mode_0').checked) { e.style.display = "none"; } else { e.style.display = "block"; }
        }
    //-->
</script>
<fieldset>
    <p><__trans phrase="In order to use the <strong>http:BL</strong> system, you must enter your key.  If you don't have a key, you can get one for free at "><a href="http://www.projecthoneypot.org/httpbl_configure.php">Project Honey Pot</a>.</p>
    <mtapp:setting
        id="httpbl_key"
        label="<__trans phrase="Access Key">"
        hint=""
        show_hint="0">
        <p>
            <__trans phrase="Enter your <strong>http:BL</strong> access key here:">
            <input id="httpbl_key" name="httpbl_key" size="12" <mt:if name="httpbl_key">value="<mt:var name="httpbl_key">"</mt:if> />
        </p>
    </mtapp:setting>
    <p><__trans phrase="The age threshold allows you to control the freshness of the data returned by the <strong>http:BL</strong> lookup.  If the age of the last activity is older than the value you specify here, this test will be ignored.  Currently, the age ranges from 0-255.  To disable entirely, turn off or set to 0.  To catch anything in the system, set this value to 255."></p>
    <mtapp:setting
        id="httpbl_age_mode"
        label="<__trans phrase="Age Action">"
        hint=""
        show_hint="0">
        <ul>
            <li><input onclick="toggleSubPrefs(this); hide_and_seek()" type="radio" id="httpbl_age_mode_0" name="httpbl_age_mode" value="0" <mt:unless name="httpbl_age_mode">checked="checked"</mt:unless> /> <__trans phrase="Off"></li>
            <li><input onclick="toggleSubPrefs(this); hide_and_seek()" type="radio" id="httpbl_age_mode_2" name="httpbl_age_mode" value="2" <mt:if name="httpbl_age_mode_2">checked="checked"</mt:if> /> <__trans phrase="Moderate feedback from throttled records"></li>
            <li><input onclick="toggleSubPrefs(this); hide_and_seek()" type="radio" id="httpbl_age_mode_1" name="httpbl_age_mode" value="1" <mt:if name="httpbl_age_mode_1">checked="checked"</mt:if> /> <__trans phrase="Junk feedback from throttled records"> (<a href="javascript:void(0)" onclick="return toggleAdvancedPrefs(event,'httpbl_age_mode_1')"><__trans phrase="Adjust scoring"></a>)
                <span id="httpbl_age_mode_1-advanced" class="setting-advanced"><__trans phrase="Score weight:">
                    <a href="javascript:void(0)" class="spinner" onclick="return junkScoreNudge(-1, 'httpbl_age_weight')"><!-- <__trans phrase="Less"> --><img src="$static/decrease.gif" alt="<__trans phrase="Decrease">" width="12" height="8" /></a>
                    <input type="text" size="3" id="httpbl_age_weight" name="httpbl_age_weight" value="<mt:var name="httpbl_age_weight" escape="html">" />
                    <a href="javascript:void(0)" class="spinner" onclick="return junkScoreNudge(1,'httpbl_age_weight')"><img src="$static/increase.gif" alt="<__trans phrase="Increase">" width="12" height="8" /><!-- <__trans phrase="More"> --></a>
                </span>
            </li>
        </ul>
    </mtapp:setting>
    <div id="httpbl_age_mode-prefs" style="display: <mt:unless name="httpbl_age_mode">none<mt:else>block</mt:unless>;">
        <mtapp:setting
            id="httpbl_age"
            label="<__trans phrase="Age Threshold:">">
            <p><input id="httpbl_age" name="httpbl_age" size="3" <mt:if name="httpbl_age">value="<mt:var name="httpbl_age">"</mt:if> /></p>
        </mtapp:setting>
    </div>
    <p><__trans phrase="The threat threshold allows you to dictate the threat level of the data returned by the <strong>http:BL</strong> lookup.  The threat score is based on a number of factors, such as the number of honey pots visited and the damage done during those visits.  If the threat score returned is lower than the value you specify here, this test will be ignored.  Currently, the threat ranges from 0-255.  To disable entirely, turn off or set to 0.  Setting to 255 will permit any threat levels through, so if you want to block even the smallest threats, set to 1, which will catch everything at that level and above."></p>
    <mtapp:setting
        id="httpbl_threat_mode"
        label="<__trans phrase="Threat Action">"
        hint=""
        show_hint="0">
        <ul>
            <li><input onclick="toggleSubPrefs(this); hide_and_seek()" type="radio" id="httpbl_threat_mode_0" name="httpbl_threat_mode" value="0" <mt:unless name="httpbl_threat_mode">checked="checked"</mt:unless> /> <__trans phrase="Off"></li>
            <li><input onclick="toggleSubPrefs(this); hide_and_seek()" type="radio" id="httpbl_threat_mode_2" name="httpbl_threat_mode" value="2" <mt:if name="httpbl_threat_mode_2">checked="checked"</mt:if> /> <__trans phrase="Moderate feedback from throttled records"></li>
            <li><input onclick="toggleSubPrefs(this); hide_and_seek()" type="radio" id="httpbl_threat_mode_1" name="httpbl_threat_mode" value="1" <mt:if name="httpbl_threat_mode_1">checked="checked"</mt:if> /> <__trans phrase="Junk feedback from throttled records"> (<a href="javascript:void(0)" onclick="return toggleAdvancedPrefs(event,'httpbl_threat_mode_1')"><__trans phrase="Adjust scoring"></a>)
                <span id="httpbl_threat_mode_1-advanced" class="setting-advanced"><__trans phrase="Score weight:">
                    <a href="javascript:void(0)" class="spinner" onclick="return junkScoreNudge(-1, 'httpbl_threat_weight')"><!-- <__trans phrase="Less"> --><img src="$static/decrease.gif" alt="<__trans phrase="Decrease">" width="12" height="8" /></a>
                    <input type="text" size="3" id="httpbl_threat_weight" name="httpbl_threat_weight" value="<mt:var name="httpbl_threat_weight" escape="html">" />
                    <a href="javascript:void(0)" class="spinner" onclick="return junkScoreNudge(1,'httpbl_threat_weight')"><img src="$static/increase.gif" alt="<__trans phrase="Increase">" width="12" height="8" /><!-- <__trans phrase="More"> --></a>
                </span>
            </li>
        </ul>
    </mtapp:setting>
    <div id="httpbl_threat_mode-prefs" style="display: <mt:unless name="httpbl_threat_mode">none<mt:else>block</mt:unless>;">
        <mtapp:setting
            id="httpbl_threat"
            label="<__trans phrase="Threat Threshold:">">
            <p><input id="httpbl_threat" name="httpbl_threat" size="3" <mt:if name="httpbl_threat">value="<mt:var name="httpbl_threat">"</mt:if> /></p>
        </mtapp:setting>
    </div>
    <p><__trans phrase="The type threshold allows you to indicate the types of visitors that you will permit in the data returned by the <strong>http:BL</strong> lookup.  If the type matches the value you specify here, this test will be triggered.  Currently, there are three type types.  You may choose any or all of them."></p>
    <mtapp:setting
        id="httpbl_type_mode"
        label="<__trans phrase="Type Threshold">"
        hint=""
        show_hint="0">
        <ul>
            <li><input onclick="toggleSubPrefs(this); hide_and_seek()" type="radio" id="httpbl_type_mode_0" name="httpbl_type_mode" value="0" <mt:unless name="httpbl_type_mode">checked="checked"</mt:unless> /> <__trans phrase="Off"></li>
            <li><input onclick="toggleSubPrefs(this); hide_and_seek()" type="radio" id="httpbl_type_mode_2" name="httpbl_type_mode" value="2" <mt:if name="httpbl_type_mode_2">checked="checked"</mt:if> /> <__trans phrase="Moderate feedback from throttled records"></li>
            <li><input onclick="toggleSubPrefs(this); hide_and_seek()" type="radio" id="httpbl_type_mode_1" name="httpbl_type_mode" value="1" <mt:if name="httpbl_type_mode_1">checked="checked"</mt:if> /> <__trans phrase="Junk feedback from throttled records"> (<a href="javascript:void(0)" onclick="return toggleAdvancedPrefs(event,'httpbl_type_mode_1')"><__trans phrase="Adjust scoring"></a>)
                <span id="httpbl_type_mode_1-advanced" class="setting-advanced"><__trans phrase="Score weight:">
                    <a href="javascript:void(0)" class="spinner" onclick="return junkScoreNudge(-1, 'httpbl_type_weight')"><!-- <__trans phrase="Less"> --><img src="$static/decrease.gif" alt="<__trans phrase="Decrease">" width="12" height="8" /></a>
                    <input type="text" size="3" id="httpbl_threat_weight" name="httpbl_type_weight" value="<mt:var name="httpbl_type_weight" escape="html">" />
                    <a href="javascript:void(0)" class="spinner" onclick="return junkScoreNudge(1,'httpbl_type_weight')"><img src="$static/increase.gif" alt="<__trans phrase="Increase">" width="12" height="8" /><!-- <__trans phrase="More"> --></a>
                </span>
            </li>
        </ul>
    </mtapp:setting>
    <div id="httpbl_type_mode-prefs" style="display: <mt:unless name="httpbl_type_mode">none<mt:else>block</mt:unless>;">
        <mtapp:setting
            id="httpbl_type"
            label="<__trans phrase="Type Action">"
            hint=""
            show_hint="0">
            <ul>
                <li><input type="checkbox" name="httpbl_type_1" id="httpbl_type_1" value="1" <mt:if name="httpbl_type_1">checked="checked"</mt:if> /> <__trans phrase="Suspicious">
                <li><input type="checkbox" name="httpbl_type_2" id="httpbl_type_2" value="2" <mt:if name="httpbl_type_2">checked="checked"</mt:if> /> <__trans phrase="Harvester">
                <li><input type="checkbox" name="httpbl_type_3" id="httpbl_type_3" value="4" <mt:if name="httpbl_type_3">checked="checked"</mt:if> /> <__trans phrase="Comment Spammer">
            </ul>
        </mtapp:setting>
    </div>
</fieldset>
TMPL
}

1;
