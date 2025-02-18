package gtp5gnl

import (
	"fmt"
	"syscall"

	"github.com/khirono/go-genl"
	"github.com/khirono/go-nl"
	newnl "github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

func GetReport(c *Client, link *Link, urrid uint64, seid uint64) ([]USAReport, error) {
	return GetReportOID(c, link, OID{uint64(urrid), seid})
}

func GetUsageStatistic(c *Client, link *Link) (*UsageStatistic, error) {
	flags := syscall.NLM_F_ACK
	req := nl.NewRequest(c.ID, flags)

	err := req.Append(genl.Header{Cmd: CMD_GET_USAGE_STATISTIC})
	if err != nil {
		return nil, err
	}

	err = req.Append(nl.AttrList{
		{
			Type:  LINK,
			Value: nl.AttrU32(link.Index),
		},
	})
	if err != nil {
		return nil, err
	}

	rsps, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	if len(rsps) < 1 {
		return nil, fmt.Errorf("nil Usage Statistic")
	}
	ustat, err := DecodeUsageStatistic(rsps[0].Body[genl.SizeofHeader:])
	if err != nil {
		return nil, err
	}
	return ustat, err
}

func GetReportOID(c *Client, link *Link, oid OID) ([]USAReport, error) {
	flags := syscall.NLM_F_ACK
	req := nl.NewRequest(c.ID, flags)
	err := req.Append(genl.Header{Cmd: CMD_GET_REPORT})
	if err != nil {
		return nil, err
	}
	urrid, ok := oid.ID()
	if !ok {
		return nil, fmt.Errorf("invalid oid: %v", oid)
	}
	err = req.Append(nl.AttrList{
		{
			Type:  LINK,
			Value: nl.AttrU32(link.Index),
		},
		{
			Type:  URR_ID,
			Value: nl.AttrU32(urrid),
		},
	})
	if err != nil {
		return nil, err
	}
	seid, ok := oid.SEID()
	if ok {
		err = req.Append(&nl.Attr{
			Type:  URR_SEID,
			Value: nl.AttrU64(seid),
		})
		if err != nil {
			return nil, err
		}
	}
	rsps, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	if len(rsps) < 1 {
		return nil, fmt.Errorf("nil Report of oid(%v)", oid)
	}
	reports, err := DecodeAllUSAReports(rsps[0].Body[genl.SizeofHeader:])
	if err != nil {
		return nil, err
	}
	return reports, err
}

// map[uint64][]uint32 // key: seid, value: urrids
func GetMultiReports(c *Client, link *Link, lSeidUrridsMap map[uint64][]uint32) ([]USAReport, error) {
	var oids []OID
	for seid, urrIds := range lSeidUrridsMap {
		for _, urrId := range urrIds {
			oids = append(oids, OID{seid, uint64(urrId)})
		}
	}
	return GetMultiReportsOID(c, link, oids)
}

func GetMultiReportsOID(c *Client, link *Link, oids []OID) ([]USAReport, error) {
	var attrs []nl.Attr

	flags := syscall.NLM_F_ACK
	req := nl.NewRequest(c.ID, flags)
	err := req.Append(genl.Header{Cmd: CMD_GET_MULTI_REPORTS})
	if err != nil {
		return nil, err
	}
	err = req.Append(nl.AttrList{
		{
			Type:  LINK,
			Value: nl.AttrU32(link.Index),
		},
		{
			Type:  URR_NUM,
			Value: nl.AttrU32(len(oids)),
		},
	})
	if err != nil {
		return nil, err
	}

	for _, oid := range oids {
		urrid, ok := oid.ID()
		if !ok {
			return nil, fmt.Errorf("invalid oid: %v", oid)
		}

		seid, ok := oid.SEID()
		if ok {
			attrs = append(attrs, nl.Attr{
				Type: URR_MULTI_SEID_URRID,
				Value: nl.AttrList{
					{
						Type:  URR_ID,
						Value: nl.AttrU32(urrid),
					},
					{
						Type:  URR_SEID,
						Value: nl.AttrU64(seid),
					},
				},
			},
			)
		}
	}
	err = req.Append(nl.AttrList(attrs))
	if err != nil {
		return nil, err
	}

	rsps, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	if len(rsps) < 1 {
		return nil, fmt.Errorf("nil Report")
	}
	reports, err := DecodeAllUSAReports(rsps[0].Body[genl.SizeofHeader:])
	if err != nil {
		return nil, err
	}
	// fmt.Printf(">>> reports: %+v\n", spew.Sdump(reports))
	return reports, err
}

func GetMultiReportsOIDv2(c *Client, link *Link, oids []OID) ([]USAReport, error) {
	msg := &newnl.Genlmsg{
		Command: CMD_GET_MULTI_REPORTS,
	}

	flags := syscall.NLM_F_ACK
	req := newnl.NewNetlinkRequest(c.ID, flags)
	req.AddData(msg)

	req.AddData(newnl.NewRtAttr(LINK, newnl.Uint32Attr(uint32(link.Index))))
	req.AddData(newnl.NewRtAttr(URR_NUM, newnl.Uint32Attr(uint32(len(oids)))))

	for _, oid := range oids {
		urrid, ok := oid.ID()
		if !ok {
			return nil, fmt.Errorf("invalid oid: %v", oid)
		}
		seid, ok := oid.SEID()
		if ok {
			urrsData := newnl.NewRtAttr(URR_MULTI_SEID_URRID|int(newnl.NLA_F_NESTED), nil)
			urrsData.AddChild(newnl.NewRtAttr(URR_ID, newnl.Uint32Attr(uint32(urrid))))
			urrsData.AddChild(newnl.NewRtAttr(URR_SEID, newnl.Uint64Attr(seid)))
			req.AddData(urrsData)
		}
	}

	// fmt.Printf("###>>> req: %+v\n", req)
	msgs, err := req.Execute(unix.NETLINK_GENERIC, 0)
	if err != nil {
		return nil, err
	}

	// fmt.Printf("##>>> msgs: %+v\n", spew.Sdump(msgs))
	reports, err := DecodeAllUSAReports(msgs[0][genl.SizeofHeader:])
	if err != nil {
		return nil, err
	}
	// fmt.Printf("###>>> reports: %+v\n", spew.Sdump(reports))
	return reports, err
}
