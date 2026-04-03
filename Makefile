all: matterbridge

matterbridge:
	go build -tags noapi,nodiscord,noharmony,noirc,nokeybase,nomatrix,nomsteams,nomumble,nonctalk,norocketchat,noslack,nosshchat,nosteam,notelegram,novk,nowhatsapp,noxmpp,nozulip .

matterbridge-arm:
	GOARCH=arm GOARM=6 GOOS=linux go build -o $@ -tags noapi,nodiscord,noharmony,noirc,nokeybase,nomatrix,nomsteams,nomumble,nonctalk,norocketchat,noslack,nosshchat,nosteam,notelegram,novk,nowhatsapp,noxmpp,nozulip .
