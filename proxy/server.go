package proxy

import (
	"crypto/tls"
	"net"

	"github.com/p4gefau1t/trojan-go/common"
	"github.com/p4gefau1t/trojan-go/conf"
	"github.com/p4gefau1t/trojan-go/protocol"
	"github.com/p4gefau1t/trojan-go/protocol/direct"
	"github.com/p4gefau1t/trojan-go/protocol/trojan"
	"github.com/p4gefau1t/trojan-go/stat"
	"github.com/valyala/tcplisten"
	"github.com/xtaci/smux"
)

type Server struct {
	config *conf.GlobalConfig
	common.Runnable
	auth  stat.Authenticator
	meter stat.TrafficMeter
}

func (s *Server) handleMuxConn(stream *smux.Stream) {
	inboundConn, err := trojan.NewInboundConnSession(stream, s.config, s.auth)
	inboundConn.(protocol.NeedMeter).SetMeter(s.meter)
	if err != nil {
		stream.Close()
		logger.Error(common.NewError("cannot start inbound session").Base(err))
		return
	}
	defer inboundConn.Close()
	req := inboundConn.GetRequest()
	if req.Command != protocol.Connect {
		logger.Error("mux only support tcp now")
		return
	}
	outboundConn, err := direct.NewOutboundConnSession(nil, req)
	if err != nil {
		logger.Error(err)
		return
	}
	logger.Info("mux tunneling to", req.String())
	defer outboundConn.Close()
	proxyConn(inboundConn, outboundConn)
}

func (s *Server) handleConn(conn net.Conn) {
	inboundConn, err := trojan.NewInboundConnSession(conn, s.config, s.auth)

	if err != nil {
		logger.Error(err)
		return
	}
	req := inboundConn.GetRequest()

	if req.Command == protocol.Mux {
		muxServer, err := smux.Server(conn, nil)
		defer muxServer.Close()
		common.Must(err)
		for {
			stream, err := muxServer.AcceptStream()
			if err != nil {
				logger.Error(err)
				return
			}
			go s.handleMuxConn(stream)
		}
	}
	inboundConn.(protocol.NeedMeter).SetMeter(s.meter)

	if req.Command == protocol.Associate {
		inboundPacket, _ := trojan.NewPacketSession(inboundConn)
		defer inboundPacket.Close()

		outboundPacket, err := direct.NewOutboundPacketSession()
		if err != nil {
			logger.Error(err)
			return
		}
		defer outboundPacket.Close()
		logger.Info("UDP associated")
		proxyPacket(inboundPacket, outboundPacket)
		logger.Info("UDP tunnel closed")
		return
	}

	defer inboundConn.Close()
	outboundConn, err := direct.NewOutboundConnSession(nil, req)
	if err != nil {
		logger.Error(err)
		return
	}
	defer outboundConn.Close()

	logger.Info("conn from", conn.RemoteAddr(), "tunneling to", req.String())
	proxyConn(inboundConn, outboundConn)
}

func (s *Server) Run() error {
	tlsConfig := &tls.Config{
		Certificates: s.config.TLS.KeyPair,
		CipherSuites: s.config.TLS.CipherSuites,
	}
	if s.config.MySQL.Enabled {
		db, err := common.ConnectDatabase(
			"mysql",
			s.config.MySQL.Username,
			s.config.MySQL.Password,
			s.config.MySQL.ServerHost,
			s.config.MySQL.ServerPort,
			s.config.MySQL.Database,
		)
		if err != nil {
			return common.NewError("failed to connect to database server").Base(err)
		}
		s.auth, err = stat.NewMixedAuthenticator(s.config, db)
		if err != nil {
			return common.NewError("failed to init auth").Base(err)
		}
		s.meter, err = stat.NewDBTrafficMeter(db)
		if err != nil {
			return common.NewError("failed to init traffic meter").Base(err)
		}
	} else {
		s.auth = &stat.ConfigUserAuthenticator{
			Config: s.config,
		}
		s.meter = &stat.EmptyTrafficMeter{}
	}
	logger.Info("Server running at", s.config.LocalAddr)
	if s.config.TCP.ReusePort || s.config.TCP.FastOpen || s.config.TCP.NoDelay {
		cfg := tcplisten.Config{
			ReusePort:   s.config.TCP.ReusePort,
			FastOpen:    s.config.TCP.FastOpen,
			DeferAccept: s.config.TCP.NoDelay,
		}
		network := "tcp6"
		if s.config.LocalIP.To4() != nil {
			network = "tcp4"
		}
		listener, err := cfg.NewListener(network, s.config.LocalAddr.String())
		if err != nil {
			return err
		}
		for {
			conn, err := listener.Accept()
			if err != nil {
				logger.Warn(err)
				continue
			}
			tlsConn := tls.Server(conn, tlsConfig)
			err = tlsConn.Handshake()
			if err != nil {
				logger.Warn(err)
				tlsConn.Close()
				continue
			}
			go s.handleConn(tlsConn)
		}
	} else {
		listener, err := tls.Listen("tcp", s.config.LocalAddr.String(), tlsConfig)
		if err != nil {
			return err
		}
		for {
			tlsConn, err := listener.Accept()
			if err != nil {
				err = common.NewError("tls handshake failed").Base(err)
				logger.Warn(err)
				tlsConn.Close()
				continue
			}
			go s.handleConn(tlsConn)
		}

	}
}