<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xmlns:py="http://purl.org/kid/ns#"
    py:extends="'master.kid'">
<head>
<meta content="text/html; charset=utf-8" http-equiv="Content-Type" py:replace="''"/>
<title>${page.pagename} - 20 Minutes wiki</title>
</head>
<body>
        <div style="float:right; width: 10em">
            Viewing <span py:replace="page.pagename">Page Name Goes Here</span>
            <br/>
            You can return to the <a href="/">FrontPage</a>.
        </div>

<h1>International Fooball League Stats</h1>
<h2>Teams</h2>
${teams_widget.display(teams)}
<h2>Players</h2>
${players_widget.display(players)}

        <div py:replace="XML(data)">Page text goes here.</div>
    <p><a href="${tg.url('/edit', pagename=page.pagename)}">Edit this page</a></p>
</body>
</html>
