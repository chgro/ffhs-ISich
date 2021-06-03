# Distributed Denial of Service (DDoS)

Bei der Distributed Denial of Service (DDos) Attake, handelt es sich um einen gezielten Angriff auf eine Webseite oder einen zur Verfügung gestellten Dienst über eine vielzahl von Geräten (Devices). Das Ziel ist es, die Verfügbarkeit der Webseite oder des Dienstes zu stören. Ein solcher Angriff kann wirtschaftliche Folgen haben. Dabei werden die Geräte oft "ferngesteuert" und als sogenannte Bots bezeichnet. Das Netz dieser Geräte wird als Botnetz bezeichnet. Botnetze können im Dark Web bereits für kleinere Beträge gemietet werden. Die Geräte werden meist über einen Trojaner oder ein Wurm "infiziert" welcher eine Verbindung zu einem zentralen Server herstellt. Neuere Bots verbinden sich über Peer-to-Peer mit anderen Bots. Über die Bots kann weitere Malware (z.B. Keylogger, etc.) verbreitet werden.

Ein DDos-Angrriff hat zum ziel, eine Webseite mit Anfragen (Requests) zu "bombardieren", so dass die Webseite nicht mehr aufgeruffen werden kann bzw. unter der Last der Anfragen zusammenbricht.

## Angriff

## Detektion

Symptome einer DDoS Attacke sind

* Hoher Ressourcen verbrauch
* Lange Antwortzeiten
* 

## Verhinderung

Folgende Massnahmen können DDoS-Angriffe nicht komplett verhindern aber erschweren.

* Sichere Kennwörter für Router, Netzwerke und vernetzte Geräte IoT
* Filtern von ungültigen Adressen
* Sperrlisten bzw. wo möglich Allow-Listen
* Inteligente Firewalls mit DDoS-Erkennung
* Nur die wirklich benötigten Dienste aktivieren und nur die absolut notwendigen Netzwerkports öffnen.
* Einsatz von Intrusion Detection Systemen (IDS)
* Systeme "härten" (*Hardening*)
* Aktuelle Patchlevel für OS und Software

## Reaktion

Reaktion (oder Gegenmassnahmen) können sein:

* Protokollieren des Angriffs (Netflows, Server-Logs, Application-Logs, Mailverkehr mit den Erpressern, etc.).
* Minimale Kommunikationskanäle gegen aussen offen halten (statischer Webauftritt), Kunde Informieren und alternative Kontaktmöglichkeiten bieten (Telefon, Fax, E-Mail)
* Angriff analysieren.