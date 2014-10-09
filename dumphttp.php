#!/usr/bin/php
<?php
// run with source filename as argument- eats http packets and tries to follow
// the conversation, find filenames, and save headers and transferred files
// too complicated to separate headers from files! will have to do by hand w/ hex editor in case of binary files
// Expects file in libpcap's format, ie tcpdump (options) -w (filename)

// some constants
$pcapMagic = pack("N", 0xa1b2c3d4);	// expected magic number

if ($argc <> 2) {
	exit("Usage: $argv[0] filename\n");
}

$sourceFilename = $argv[1];
$baseFilename = basename($sourceFilename);
file_exists($sourceFilename) or exit("File \"$sourceFilename\" not found\n");

$sfh = fopen($sourceFilename, 'rb') or exit("Problem opening $sourceFilename\n");

//$tree[$baseFilename]["fh"] = $sfh;	// will include in our data structure, though as a shortcut mostly will refer as $sfh (source file handle)
// don't think i ever use this...

// read in header, make sure we have correct type of file
$dumpHead = fread($sfh, 24);
if (feof($sfh)) {
	exit("Premature EOF: Expected 24 byte file header, got " . strlen($dumpheader) . " bytes instead.\n");
}

$fileMagic = substr($dumpHead, 0, 4);
$byteSex = "N";	// used for converting "string" of raw data to its value, assumes network byte order
if ($fileMagic != $pcapMagic) {	// actually i expect this case to fail since my machine is little-endian, but for portability...
	if ($fileMagic != strrev($pcapMagic)) {	// we check this next- if this fails, it's not the magic number in either byte sex
		exit("Unrecognized file format.\n");	// so quit
	}	// but if we get this far, file contains intel byte ordering
	$byteSex = "V";
}

if (substr($dumpHead, 4, 4) != pack(strtolower($byteSex) . "*", 0x0002, 0x0004)) {
	exit("Only coded to work with version 2.4\n");
}
if (substr($dumpHead, 20, 4) != pack($byteSex, 0x00000001)) {
	exit("Not ethernet?\n");
}

// start grabbing packets
$pktCount = 0;
while (!feof($sfh)) {
	$pktHead = fread($sfh, 16);
	if (feof($sfh)) {
		if (strlen($pktHead) == 0) {	// at this point, all remaining connections which were not closed on both ends will be eaten
			unset($tree["head"]);	// since this isn't needed anymore, and doesn't have a file handle associated...
//			var_dump($tree);	// should be nothing left
			foreach ($tree as $convID => $junk) {	// step through remaining elements, not concerned with value, only key
				munch();	// wakka wakka
				fclose($tree[$convID]["request"]["fh"]);
				fclose($tree[$convID]["response"]["fh"]);
				unset($tree[$convID]);
			}
			var_dump($tree);	// should be nothing left
			exit("No more packets.\n");
		} else {
			exit("Premature EOF: Expected 16 byte packet header, got " . strlen($pktHead) . " bytes instead.\n");
		}
	}
	$tree["head"] = unpack("{$byteSex}ts_sec/{$byteSex}ts_usec/{$byteSex}incl_len/{$byteSex}orig_len", $pktHead);
	// stores values from header in array, doing bytesex conversion if needed
	$snarflen = min($tree["head"]["incl_len"], $tree["head"]["orig_len"]);	// should be equal, but if not take the smaller
	
	$pktCount++;
	$eth = fread($sfh, $snarflen);
	if (feof($sfh)) {
		exit("Premature EOF: Packet $pktCount contained " . strlen($eth) . " bytes, expected $snarflen\n");
	}
	//echo "Packet " . $pktCount . "\tlength: " . $snarflen . "\n";
	
	// now the fun part starts- decoding the packets themselves
//echo "Packet $pktCount contains $snarflen bytes.  Protocols found: eth";
	$type = bin2hex(substr($eth, 12, 2));	// ethertype - 0x0800 = IPv4, 0x0806 = ARP
	if ($type == "0800") {	// if not IPv4, we don't care
		$ip = substr($eth, 14);	// strip off eth header, leave IP packet
		$sip = bin2hex(substr($ip, 12, 4));	// source IP address
		$dip = bin2hex(substr($ip, 16, 4));	// destination IP address
		$proto = bin2hex(substr($ip, 9, 1));
		if ($proto == "06") {	// if not tcp, we don't care
//echo " tcp";
			$iphlen = (hexdec(bin2hex(substr($ip,0,1))) & 0x0f)*4;	// find length of ip header
			$iptlen = (hexdec(bin2hex(substr($ip,2,2))));	// find total length of packet (needed b/c ps3 will pad eth to 56 bytes, though tcp+ip = 54
			$tcp = substr($ip, $iphlen, ($iptlen-$iphlen));	// strip away the ip and any padding
			$sport = bin2hex(substr($tcp, 0, 2));
			$dport = bin2hex(substr($tcp, 2, 2));
			if ($sport == "0050" or $dport == "0050") {	// if not http, we don't care
//echo " http";
				if ($dport == "0050") {
					$convID = "$sip.$sport-$dip.$dport";
					$dir = "request";
				} else {
					$convID = "$dip.$dport-$sip.$sport";
					$dir = "response";
				}
				$tcphlen = (hexdec(bin2hex(substr($tcp, 12, 1))) & 0xf0) / 4;	// find length of tcp header
				$http = substr($tcp, $tcphlen);	// throw away tcp header, leaving http message
				//$http = strlen(substr($tcp, $tcphlen));
				//echo "$convID\t$iphlen\t$tcphlen\t$http\t$dir\n";
				$tcpSeq = hexdec(bin2hex(substr($tcp, 4, 4)));	//grab the sequence number
				$tcpFlags = hexdec(bin2hex(substr($tcp, 13, 1)));
				$tcpFIN = $tcpFlags & 1;
				$tcpSYN = $tcpFlags & 2;
				if ($tcpSYN) {	// new connection
//echo " SYN";
					$tree[$convID][$dir]["iSeq"] = $tcpSeq;	// store this as the initial sequence number
//					$tree[$convID][$dir]["fh"] = fopen("$convID.$dir", "w");
					$tree[$convID][$dir]["fh"] = tmpfile();
					// one drawback here, if a second syn on a particular connection is received, the first file handle will be orphaned,
					// but not a huge problem since it would have likely been empty anyway- only case where it might not is if a particular
					// source port gets re-used for a separate connection, but i'll worry about that if it happens... should throw an error i think
				}
				if ($tfh = $tree[$convID][$dir]["fh"]) {	// because if not, this is a stray packet that doesn't fit an existing connection, throw it away
					// Yes this is what i intended- not testing if they are equal, testing if the one exists, and as
					// a side effect, assign the klunky named tree leaf to a temporary much shorter name
//echo "\nWriting ";
					$offset = $tcpSeq - $tree[$convID][$dir]["iSeq"] -1;
					fseek($tfh, $offset);	// if packets come in out of order, no matter, put them in their proper place
					fwrite($tfh, $http);	// also, duplicate packets should just overwrite each other with same data
//echo " bytes to $convID $dir at position $offset";
					if ($tcpFIN) {	// end of conversation (at least this side of it)
						$tree[$convID][$dir]["fin"] = TRUE;
						if ($tree[$convID]["request"]["fin"] and $tree[$convID]["response"]["fin"]) {	// make sure both sides of the convo have closed
//						if ($dir == "response") {	// this doesn't work as-is, sometimes server sends fin before response (which makes no sense, but it happens)
							// but if response closes first, there likely won't be any more request
							munch();	// eat temp files, spit out head/body files
							fclose($tree[$convID]["request"]["fh"]);
							fclose($tree[$convID]["response"]["fh"]);
							unset($tree[$convID]);
						}
					}
				}
			}
		}
	}
//echo "\n";
}

function munch() {
	global $tree, $convID, $tqfh, $tafh, $baseFilename;
	fseek($tqfh = $tree[$convID]["request"]["fh"], 0, SEEK_END);	// set pointer to end (used to find total length)
	fseek($tafh = $tree[$convID]["response"]["fh"], 0, SEEK_END);	// also sets easier names to use temporarily
	$qlen = ftell($tqfh);
	$alen = ftell($tafh);
	rewind($tqfh);	// reset request tempfile handle's pointer
	rewind($tafh);	// reset response ("answer") tempfile handle's pointer
	$hfh = fopen("$baseFilename.$convID.head", "x") or exit("File $baseFilename.$convID.head already exists?\n");
//	$hqfh = fopen("$baseFilename.$convID.request.head", "x") or exit("File $baseFilename.$convID.request.head already exists?\n");
//	$hafh = fopen("$baseFilename.$convID.response.head", "x") or exit("File $baseFilename.$convID.response.head already exists?\n");
	// create permanant file to hold headers, complain if already exists
	$reqCount = $respCount = 0;	// reset bunch of counters
	while (ftell($tqfh) < $qlen) {	// loop will track remaining bytes?
		$chunk = $close = $anobody = $fileExt = $qbodylen = $abodylen = FALSE;	// reset flags
		$reqCount++;
//		fwrite($hqfh, "Request #$reqCount\n");	// label this request in header file
//		fwrite($hqfh, $line = fgets($tqfh));	// copy a line from temp to perm, keeping copy to examine
		fwrite($hfh, "Request #$reqCount\n");	// label this request in header file
		fwrite($hfh, $line = fgets($tqfh));	// copy a line from temp to perm, keeping copy to examine
		sscanf($line, "%s %s %s", $meth, $uri, $vers);
		switch($meth) {
			case "HEAD":	// neither has a body
			$anobody = TRUE;	// since this is the unusual condition
			case "GET":	// request has only header
			$qbody = FALSE;
			break;
			case "POST":	// request contains a body
			$qbody = TRUE;
			break;
			default:	// if anything else
//			exit("Unrecognized method in file $baseFilename.$convID.request.head: $line\n");
			exit("Unrecognized method in file $baseFilename.$convID.head: $line\n");
		}
		while (($line != "\r\n") and (ftell($tqfh) < $qlen)) {	// this way we caught newline on prev iteration
			fwrite($hfh, $line = fgets($tqfh));	// grab another req header
//			fwrite($hqfh, $line = fgets($tqfh));	// grab another req header
			sscanf($line, "%s %s", $headKey, $headValue);	// grab pairs from header line
			switch (strtolower($headKey)) {
				case "content-length:":
				$qbodylen = $headValue;
				break;
				case "content-type:":
				switch ($headValue) {	// most will use default's simple mapping, but a few exceptions...
					case "text/plain":
					$fileExt = ".txt";
					break;
					case "application/x-javascript":
					$fileExt = ".js";
					break;
					case "application/x-shockwave-flash":
					$fileExt = ".swf";
					break;
					default:
					$fileExt = "." . str_replace("/", ".", $headValue);	// file extension is mime type with / replaced with .
				}
				break;
				case "transfer-encoding:":
				if (strtolower($headValue) == "chunked") {
					$chunk = TRUE;
				}
				break;
				case "connection:":
				if (strtolower($headValue) == "close") {
					$close = TRUE;	// should be safe to grab all data after end of headers
				}
				break;
			}
		}
		if ($qbody) {
			$bqfh = fopen("$baseFilename.$convID.body.$reqCount.request$fileExt", "x") or exit("File $baseFilename.$convID.body.$reqCount.request$fileExt exists?\n");
			if ($chunk) {	// most complicated possibility
				while (ftell($tqfh) < $qlen) {
					$chunklen = hexdec(fgets($tqfh));
					if ($chunklen) {
						fwrite($bqfh, fread($tqfh, $chunklen));
					}
					fgets($tqfh);	// takes care of newline after payload, if none there will be no next iteration of while loop
				}
			} elseif ($qbodylen) {
				//echo "Length of $convID.request.$reqCount.body: $qbodylen\n";
				$wrote = fwrite($bqfh, fread($tqfh, $qbodylen));
//				echo "wrote $wrote bytes to file $baseFilename.$convID.request.$reqCount.body\n";
			} else {	// if neither of the previous, assume connection closes to signal eof
//				exit("$convID.request.$reqCount has no content length, chunks, or close!\n");
				fwrite ($bqfh, fread($tqfh, $qlen));	// qlen will be longer than we need, but shouldn't be a problem
			}
			fclose($bqfh);	// done with this body
		}
		fwrite($hfh, "Response #$reqCount\n");	// label this response in header file
//		fwrite($hafh, "Response #$reqCount\n");	// label this response in header file
		$close = $chunk = $line = $fileExt = $zipExt = FALSE;	// reset these flags again- also have to clear $line, otherwise this loop won't run the first time
		while (($line != "\r\n") and (ftell($tafh) < $alen)) {	// loop will track remaining bytes?
			fwrite($hfh, $line = fgets($tafh));	// copy a line from temp to perm, keeping copy to examine
//			fwrite($hafh, $line = fgets($tafh));	// copy a line from temp to perm, keeping copy to examine
			sscanf(str_replace(";", " ", $line), "%s %s", $headKey, $headValue);	// replace ; with " " so we won't grab ;charset=blah
			switch (strtolower($headKey)) {
				case "http/1.0":
				$close = TRUE;	// if 1.0, there will be no chunks, no keepalives
				case "http/1.1":
				if (($headValue == "204") or ($headValue == "304") or (substr($headValue, 0, 1) == "1")) {
					$anobody = TRUE;
				}
				break;
				case "content-type:":
				switch ($headValue) {	// most will use default's simple mapping, but a few exceptions...
					case "text/plain":
					$fileExt = ".txt";
					break;
					case "application/x-javascript":
					$fileExt = ".js";
					break;
					case "application/x-shockwave-flash":
					$fileExt = ".swf";
					break;
					default:
					$fileExt = "." . str_replace("/", ".", $headValue);	// file extension is mime type with / replaced with .
				}
				break;
				case "content-encoding:":
				switch ($headValue) {
					case "gzip":
					$zipExt = ".gz";
					break;
					case "compress":
					$zipExt = ".z";
					break;
				}
				break;
				case "content-length:":
				$abodylen = $headValue;
				break;
				case "transfer-encoding:":
				if (strtolower($headValue) == "chunked") {
					$chunk = TRUE;
				}
				break;
				case "connection:":
				if (strtolower($headValue) == "close") {
					$close = TRUE;	// should be safe to grab all data after end of headers
				}
				break;
			}
		}
		if (!$anobody) {	// if there is a body
			$bafh = fopen("$baseFilename.$convID.body.$reqCount.response$fileExt$zipExt", "x") or exit("File $baseFilename.$convID.body.$reqCount.response$fileExt$zipExt exists?\n");
			if ($chunk) {	// most complicated possibility
				while (ftell($tafh) < $alen) {
					$chunklen = hexdec(fgets($tafh));
					if ($chunklen) {
						fwrite($bafh, fread($tafh, $chunklen));
						fgets($tafh);	// takes care of newline after payload, if none there will be no next iteration of while loop
					} else {	// if chunklen is 0, that was last chunk
						fgets($tafh);	// eat extra newline
//						fgets($tafh);	// eat extra newline
						break;	// and jump out of chunk eating loop, back to parsing
					}
				}
			} elseif ($abodylen) {
				//echo "Length of $convID.request.$reqCount.body: $qbodylen\n";
				$wrote = fwrite($bafh, fread($tafh, $abodylen));
//				echo "wrote $wrote bytes to file $baseFilename.$convID.response.$reqCount.body$fileExt$zipExt\n";
			} else {
//				exit("$convID.response.$reqCount has no content length, chunks, or close!\n");
				fwrite ($bafh, fread($tafh, $alen));	// alen will be longer than we need, but shouldn't be a problem
			}
			fclose($bafh);	// done with this body
		}
	}
}						
?>
