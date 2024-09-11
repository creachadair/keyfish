# keyfish

Keyfish is a site-specific password generator and manager.  It is very much a
personal project, and if you are looking for such a tool for your own use, I
strongly recommend instead using one of the many more mature open source and
commercial products designed for this purpose. Keyfish is idiosyncratic and
unpolished, and does not aspire to greatness.

Nonetheless, if, having been so cautioned you remain curious, feel free to
explore.

## History

Around 1996 or 1997 as the web was starting to really take off, I ran into a
problem that everyone has now, which is that it's hard to keep track of all the
passwords you need to sign in to your various accounts. Today there are lots of
good tools to help with this, but at that time -- assuming you didn't just
reuse the same password for everything like your parents -- the state of the
art was a post-it note or a sheet of paper.

Somewhere on Usenet I stumbled across the idea of a "password generator", the
idea that you'd take the name of each site you wanted to sign into and combine
it with one really good-quality secret passphrase to get a password for that
specific site. The idea appealed to me, because it meant you could keep all the
non-secret details like the site address, your username, etc., in a plain text
file, and even if someone stole that file they wouldn't get your passwords.

I wrote a simple version of this in Perl (boringly named `pwgen`), which at
first just consisted of concatenating the site address with the secret
passphrase and hashing it.  Schematically:

    SHA1("www.example.com" || "my-excellent-secret-passphrase")

To turn that into a password, I'd take some bytes off the hash and use them to
index into the English alphabet. SHA1 has twenty bytes to work with, which is
plenty given that a lot of sites wouldn't even accept passwords longer than 8
characters.

The configuration file was a plain CSV text file with one line per site, having
a short label and the site name, e.g.,

    bank,www.bank.com
    blog,myblog.wordpress.com

A year or two later, I rewrote `pwgen` in Python as a learning project. By that
point I'd already run into some complications:

1. You need a way to change your password. Sites were forever making you do
   this, supposedly as a security measure.

2. Sites have different rules about password length and composition. Some sites
   required at least one digit, others required a combination of digits and
   punctuation, etc.

And of course, many sites only accepted _certain_ punctuation, thanks to poor
string escaping hygiene in popular web frameworks.

So as part of the rewrite, I made the algorithm a bit more complicated: Instead
of plain SHA1, I used the HMAC construction (mostly because I'd read about it
and thought it sounded neat), and added in a "salt" value so you could get a
new password without changing the site name. Roughly:

    HMAC(SHA1, "my-excellent-secret-passphrase", "www.example.com" || "/" || "salt")

The text file expanded a bit to make room for a password length (so I could
change the default for picky sites) and rules about the password shape
(letters, digits, punctuation). By this point, some sites had gotten so picky
that I included a rudimentary "format" setting, which would specify a template
for the password, with placeholders for the various character types. For
example, if a site required at least two digits not at the end, you could say:

    ****#*#*

which means "four letters, a digit, a letter, a digit, and a letter". I soon
had to add more placeholders for punctuation, since barely any two sites could
agree on which symbols were safe enough for commerce.

That version remained largely unchanged for several years, until late 2011 when
I started learning Go for a work project, and decided I would implement `pwgen`
yet again as a learning project. I decided to rename it `keyfish`, because I
had this little fish icon I'd bought from an artist for my blog, and I wanted
to do something with it. The Go version came with several more changes:

- I switched the algorithm to HMAC/SHA256.

- I converted the config file from plain text to JSON, so it would be easier to
  add defaults, flags, etc.

- I built a parallel implementation in JavaScript as a Chrome extension, using
  the same config file format, so that I could use it from the browser.

This repository is the slow evolution of that initial Go implementation.  Over
the years since 2012, I've made various small-to-medium changes:

- After several rounds of fighting with Chrome's increasingly Draconian
  policies about extensions, I gave up on the extension and implemented a web
  app as a separate server.

- I added more and more metadata to the config file, to keep track of all the
  nonsense you need to log into things: Security questions and their answers,
  confirmation PINs, which e-mail address I'd used to sign up, and so on.

- I added the ability to store TOTP keys and to have the tool (and its web app)
  generate TOTP codes so I wouldn't have to screw around with the authenticator
  app so much.

Unfortunately, some of these changes meant adding a lot more sensitive data to
the configuration file. Whereas the original file was pretty much just a list
of website names and some password rules, now it contains things that you
really don't want lying around in plaintext.

Over the intervening years, a bunch of tools came out to manage passwords.  I'd
tried several of them, but kept coming back to my old familiar thing, despite
its deficiencies. The ability to bake the whole thing into a single static
command-line binary was really useful.

Finally, though, I decided it was past time to switch to a properly-encrypted
storage format. To avoid having to change all my passwords all at once, I kept
the same HMAC-based password generation scheme as a default option. Now,
though, the configuration data are encrypted with an AEAD on ChaCha20-Poly1305
using a storage format inspired by the one my teammates designed for the
[setec](https://github.com/tailscale/setec) tool we built together.

With an encrypted config file, it's no longer necessary to keep track of key
generation salts and such; when I have to change a password I can just generate
a new one at random and store it in the file. This also means I can safely keep
security questions, access PINs, and so on in there.

The config data are still JSON (prior to encryption), but I cleaned up and
simplified the format a bit. I wrote a tool to translate the old format into
the new one, and wrote some library code to make it easier to work with.

Moreover, I also reworked the old web app quite a bit. Although I'd made some
refinements over the years, it wasn't very well-structured, so I took the
opportunity to make it at least a little bit less 90's vintage. It's still not
going to win any design awards, but at least it's a little cleaner. I took
advantage of the [htmx](https://htmx.org/) library to make the plumbing a
little nicer.

Hopefully this will hold me for a few more years. Come back in another decade,
and we'll see what's become of it all.

## Usage Outline

1. Create a new empty database.

    ```shell
    % kf db create example.db
    New database passphrase: ........
    Confirm new database passphrase: ........
    Created database "example.db"
    ```

2. (Optional) Set the database location in the environment:

    ```shell
    export KEYFISH_DB=$PWD/example.db
    ```

3. Add a record:

    ```shell
    % kf record add -edit email
    Passphrase: ........
    ```

    The editor will run to edit the record in YAML format.
    For this example:

    ```yaml
    label: email
    title: Personal email account
    hosts: mail.example.com
    username: aloysius
    ```

    Save and exit the editor, then:

    ```shell
    ▷ Keep changes? (y/n) y
    <saved>
    Created new record "email"
    ```

4. Set the password on a record:

    ```shell
    $ kf random 20 -set email
    Passphrase: ........
    Setting password on record "email"
    <saved>
    JfYN2JpcVP70Se2VMXxW
    ```

    Your output will be different, as the password is generated randomly.  Use
    `--copy` if you want to copy the password to the clipboard instead of
    printing it. When you do this, it will print a human-readable confirmation
    nonce instead, e.g.,

    ```shell
    % kf random 20 -set email -copy
    Passphrase:
    Setting password on record "email"
    <saved>
    ovary-heath-waist-zebra
    ```

5. Copy the password for a record:

    ```shell
    % kf copy email
    Passphrase: .........
    ovary-heath-waist-zebra
    ```

6. Run a local web app to access the database from a browser:

    ```shell
    % kf web -addr localhost:8422
    Passphrase: ........
    2024/05/03 12:24:58 Serving at "localhost:8422"
    2024/05/03 12:24:58 Watching for updates at "/home/aloysius/example.db"
    ```

    Visit `http://localhost:8422/` in a browser to use the app.

    If you want to access it from anywhere but localhost you will need to set
    up access control separately. I use [`tailscale serve`][tss] to expose mine
    to just the computers on my home tailnet, e.g.,

     ```shell
     % tailscale serve --bg --https 8422 localhost:8422
     Available within your tailnet:

     https://example.tail1234.ts.net:8422/
     |-- proxy http://127.0.0.1:8422

     Serve started and running in the background.
     To disable the proxy, run: tailscale serve --https=8422 off
     ```

     For example screenshots of the UI, see [docs](./docs/web.md).

[tss]: https://tailscale.com/kb/1242/tailscale-serve
