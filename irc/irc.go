// Copyright (c) Marius Börschig. All rights reserved.
// Licensed under the BSD-3-Clause License.
package irc
// the main IRC definitions
// see doc/*.txt 
import (
    "strings"
    "fmt"
)
const (
    IRC_ping_timeout int64  = 5
    IRC_valid_user_modes string = "iwoOra" //obsolete: "s"
    IRC_valid_channel_modes string = "opsitnbv" //obsolete: "s"
    IRC_valid_channel_prefix string = "&#+!"
    IRC_max_channel_name_length int = 50
    IRC_max_message_length int = 512
)
func IsChannelName(in string) bool {
    for _, p := range IRC_valid_channel_prefix {
        if strings.HasPrefix(in, string(p)) {
            return true
        }
    }
    return false
}
func IsValidUserMode(mod byte) bool {
    return strings.Index(IRC_valid_user_modes, string(mod)) != -1
}
func UserMaySetMode(mod byte) bool {
    return mod != 'O' && mod != 'o'
}
func UserMayClearMode(mod byte) bool{
    return mod != 'a'
}
func IsValidChannelMode(mod byte) bool {
    return strings.Index(IRC_valid_channel_modes, string(mod)) != -1
}
type NumericReply uint

func (self NumericReply) String() string {
    return fmt.Sprintf("%03d", self)
}
//Numeric Replies and Error Codes
const ( //XXX there must be a cleaner way, without all the NumericReply boilerplate
    // registration / new client
    RPL_WELCOME NumericReply = 001
    RPL_YOURHOST NumericReply = 002
    RPL_CREATED NumericReply = 003
    RPL_MYINFO NumericReply = 004
    RPL_TRYAGAIN NumericReply = 263
    //RFC 2813 sys we SHALL send LUSERS on connect
    RPL_LUSERCLIENT NumericReply = 251
    RPL_LUSEROP NumericReply = 252
    RPL_LUSERUNKOWN NumericReply = 253
    RPL_LUSERCHANNELS NumericReply = 254
    RPL_LUSERME NumericReply = 255
    // WHO
    RPL_WHOREPLY NumericReply = 352
    RPL_ENDOFWHO NumericReply = 315
    //Numeric Replies
    // NICK
    ERR_NONICKNAMEGIVEN NumericReply = 431
    ERR_ERRONEUSNICKNAME NumericReply = 432
    ERR_NICKNAMEINUSE NumericReply = 433
    ERR_NICKCOLLISION NumericReply = 436
    ERR_NOTREGISTERED NumericReply = 451
    // USER
    ERR_NEEDMOREPARAMS NumericReply = 461
    ERR_ALREADYREGISTRED NumericReply = 462
    //MODE
    ERR_UMODEUNKNOWNFLAG NumericReply = 501
    ERR_USERSDONTMATCH NumericReply = 502
    RPL_UMODEIS NumericReply = 221
    ERR_UNKNOWNMODE NumericReply = 472
    // INFO
    RPL_INFO NumericReply = 371
    RPL_ENDOFINFO NumericReply = 374
    //MODE channel
    RPL_BANLIST NumericReply = 367
    RPL_ENDOFBANLIST NumericReply = 368
    RPL_EXCEPTLIST NumericReply = 348
    RPL_ENDOFEXCEPTLIST NumericReply = 349
    RPL_INVITELIST NumericReply = 346
    RPL_ENDOFINVITELIST NumericReply =347
    RPL_UNIQOPIS NumericReply = 325
    RPL_CHANNELMODEIS NumericReply = 324
    ERR_USERNOTINCHANNEL NumericReply = 441
    ERR_NOCHANMODES NumericReply = 477
    //JOIN
    ERR_CHANNELISFULL NumericReply = 471
    ERR_INVITEONLYCHAN NumericReply = 473
    ERR_BANNEDFROMCHAN NumericReply = 474
    ERR_BADCHANNELKEY NumericReply = 475
    ERR_BADCHANMASK NumericReply = 476
    ERR_NOSUCHCHANNEL NumericReply = 403
    ERR_TOOMANYCHANNELS NumericReply = 405
    ERR_TOOMANYTARGETS NumericReply = 407
    ERR_UNAVAILRESOURCE NumericReply = 437
    RPL_NOTOPIC NumericReply = 331
    RPL_TOPIC NumericReply = 332
    RPL_TOPICWHOTIME NumericReply = 333
    RPL_NAMREPLY NumericReply = 353
    RPL_ENDOFNAMES NumericReply = 366
    // PART
    ERR_NOTONCHANNEL NumericReply = 443
    // PRIVMSG
    ERR_CANNOTSENDTOCHAN NumericReply = 404
    ERR_NORECIPIENT NumericReply = 411
    ERR_NOTEXTTOSEND NumericReply = 412
    ERR_NOTOPLEVEL NumericReply = 413
    ERR_WILDTOPLEVEL=414
    ERR_NOSUCHNICK NumericReply =  401
    ERR_NOSUCHSERVER NumericReply =  402
    // USERHOST
    RPL_USERHOST NumericReply = 302
    //WHOIS
    RPL_WHOISUSER NumericReply = 311
    RPL_WHOISSERVER NumericReply = 312
    RPL_WHOISOPERATOR NumericReply = 313
    RPL_WHOISIDLE NumericReply =317
    RPL_ENDOFWHOIS NumericReply = 318
    RPL_WHOISCHANNELS NumericReply = 319
    RPL_AWAY NumericReply = 301
    //AWAY
    RPL_UNAWAY NumericReply = 305
    RPL_NOWAWAY NumericReply = 306
)
//NumericMap maps numeric reply codes to response strings as given in the RFCs.
var NumericMap  = map[NumericReply]string{
    // registration
    RPL_WELCOME: ":Welcome to the Internet Relay Network %s", // nick!user@host
    RPL_YOURHOST: ":Your host is %s, running version %s", //servername, version
    RPL_CREATED: ":This server was created %s", //date
    RPL_MYINFO: ":%s %s %s %s", //servername version user_modes channel_modes
    RPL_LUSERCLIENT: ": There are %d users and %d services on 1 servers", //num(users), num(services)
    RPL_LUSEROP: "%d :operator(s) online",//num(operators)
    RPL_LUSERUNKOWN: "%d :unknown connection(s)", //num(unknown)
    RPL_LUSERCHANNELS: "%d :channels formed", // num(channels)
    RPL_LUSERME: ":I have %d clients and 1 servers", //num(clients)
    RPL_TRYAGAIN: "%s :Please wait a while and try again.", //command
    //NICK
    ERR_NONICKNAMEGIVEN: ":No nickname given",
    ERR_ERRONEUSNICKNAME: "%s :Erroneus nickname", //nick
    ERR_NICKNAMEINUSE: "%s :Nickname is already in use", //nick
    ERR_NICKCOLLISION: "%s :Nickname collision KILL", //nick
    ERR_NOTREGISTERED: ":You have not registered",
    // USER
    ERR_NEEDMOREPARAMS: "%s :Not enough parameters", //command
    ERR_ALREADYREGISTRED: ":You may not reregister",
    //JOIN
    ERR_CHANNELISFULL: "%s :Cannot join channel (+l)", //channel
    ERR_INVITEONLYCHAN: "%s :Cannot join channel (+i)", //channel
    ERR_BANNEDFROMCHAN: "%s :Cannot join channel (+b)", //channel
    ERR_BADCHANNELKEY: "%s :Cannot join channel (+k)", //channel
    ERR_BADCHANMASK: "%s :Bad channel mask", //channel
    ERR_NOSUCHCHANNEL: "%s :No such channel", //channel
    ERR_TOOMANYCHANNELS: "%s :You have joined too many channels", //channel
    ERR_TOOMANYTARGETS: "%s :%d recipients. %s", //target, error_code, abort_message
    ERR_UNAVAILRESOURCE: "%s :Nick/channel is temporarily unvavailable", //nick/channel
    RPL_NOTOPIC: "%s :No topic set", //channel
    RPL_TOPIC: "%s :%s", //channel topic
    RPL_TOPICWHOTIME: "%s %s %d", //channel, nick, setat_unix_timestamp
    RPL_NAMREPLY:  "%s %s :%s",  //symbol(=*@), channel, (symboL)nick ...
    RPL_ENDOFNAMES: "%s :End of NAMES list", //channel
    //PART
    ERR_NOTONCHANNEL: "%s :You're not on that channel", //channel
    //PRIVMSG
    ERR_CANNOTSENDTOCHAN: "%s :Cannot send to channel", //channel
    ERR_NORECIPIENT: ":No recipient given (%s)", //command
    ERR_NOTEXTTOSEND : "No text to send",
    ERR_NOTOPLEVEL: "%s :No toplevel domain specified", //mask
    ERR_WILDTOPLEVEL: "%s :Wildcard in toplevel domain", //mask
    ERR_NOSUCHNICK: "%s :No such nick/channel", //nick
    ERR_NOSUCHSERVER: "%s :No such server", //servername
    //WHO
    RPL_ENDOFWHO: "%s :End of WHO list", //name
    RPL_WHOREPLY: "%s %s %s %s %s %s :0 %s", //channel user host server nick mode realname
    //USERHOST
    RPL_USERHOST: ":%s", //space separated encoded replies: (nickname[*]=[+|-]hostname)
    // INFO
    RPL_INFO: ":%s", //string
    RPL_ENDOFINFO: ":End of INFO list",
    //MODE channel
    RPL_BANLIST: "%s %s", //channel banmask
    RPL_ENDOFBANLIST: "%s :End of channel ban list", //channel
    RPL_EXCEPTLIST: "%s %s", //channel exception mask
    RPL_ENDOFEXCEPTLIST: "%s :End of channel exception list",
    RPL_INVITELIST: "%s %s", //channel invitemask
    RPL_ENDOFINVITELIST: "%s :End of channel invite list", //channel
    RPL_UNIQOPIS: "%s %s", //channel, nickname
    RPL_CHANNELMODEIS: "%s %s %s", //channel, mode, modeparams
    ERR_USERNOTINCHANNEL: "%s %s: They aren't on that channel", //nick channel
    ERR_NOCHANMODES: "%s :Channel doesn't support modes", //channel
    //MODE
    ERR_UMODEUNKNOWNFLAG : "Unknown MODE flag",
    ERR_USERSDONTMATCH : "Cannot change mode for other users",
    RPL_UMODEIS : "%s",
    ERR_UNKNOWNMODE: "%s :is unknown mode char to me for %s", // char, channel
    //WHOIS
    RPL_WHOISUSER: "%s %s %s * :%s", //nick user host realname
    RPL_WHOISSERVER: "%s %s :%s", //nick, server, server_info
    RPL_WHOISOPERATOR: "%s : is an IRC operator", //nick
    RPL_WHOISIDLE : "%s %d :seconds idle", //nick, numeric_time
    RPL_ENDOFWHOIS: "%s :End of WHOIS list", //nick
    RPL_WHOISCHANNELS: "%s : %s", //nick, +@channel (might appear more than once)
    RPL_AWAY: "%s :%s", //nick, awaymsg
    //AWAY
    RPL_UNAWAY: ":You are no longer marked as being away",
    RPL_NOWAWAY: ":You have been marked as being away",
}

type Message interface {
    getRaw() *string
    getPrefix() *string
    getCommand() *string
    getParameters() []*string
    getTrailing() *string
}

