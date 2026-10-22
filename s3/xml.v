// xml renders the S3 response bodies. S3 speaks a small, fixed set of
// documents, so this builds them directly instead of pulling in a general XML
// stack. Every value is escaped; nothing reaches the wire unsanitized.
module s3

import time
import lifecycle
import store

const xmlns = 'http://s3.amazonaws.com/doc/2006-03-01/'

pub struct S3Error {
pub:
	status  int
	code    string
	message string
	bucket  string
	key     string
}

pub fn (e S3Error) body() string {
	return '<?xml version="1.0" encoding="UTF-8"?>\n<Error>\n<Code>${esc(e.code)}</Code>\n<Message>${esc(e.message)}</Message>\n<BucketName>${esc(e.bucket)}</BucketName>\n<Key>${esc(e.key)}</Key>\n</Error>\n'
}

pub fn list_buckets(owner string, buckets []string) string {
	mut items := ''
	for name in buckets {
		items += '<Bucket><Name>${esc(name)}</Name><CreationDate>${now_iso()}</CreationDate></Bucket>'
	}
	return '<?xml version="1.0" encoding="UTF-8"?>\n<ListAllMyBucketsResult xmlns="${xmlns}"><Owner><ID>${esc(owner)}</ID><DisplayName>${esc(owner)}</DisplayName></Owner><Buckets>${items}</Buckets></ListAllMyBucketsResult>\n'
}

pub fn list_objects(bucket string, stats []store.Stat, truncated bool) string {
	mut items := ''
	for stat in stats {
		items += '<Contents><Key>${esc(stat.key)}</Key><LastModified>${unix_iso(stat.modified)}</LastModified><ETag>&quot;${esc(stat.etag)}&quot;</ETag><Size>${stat.size}</Size><StorageClass>${esc(stat.storage_class)}</StorageClass></Contents>'
	}
	return '<?xml version="1.0" encoding="UTF-8"?>\n<ListBucketResult xmlns="${xmlns}"><Name>${esc(bucket)}</Name><IsTruncated>${truncated}</IsTruncated>${items}</ListBucketResult>\n'
}

pub fn location(region string) string {
	return '<?xml version="1.0" encoding="UTF-8"?>\n<LocationConstraint xmlns="${xmlns}">${esc(region)}</LocationConstraint>\n'
}

pub fn list_versions(bucket string, stats []store.Stat) string {
	mut items := ''
	for stat in stats {
		element := if stat.delete_marker { 'DeleteMarker' } else { 'Version' }
		latest := if stat.latest { 'true' } else { 'false' }
		items += '<${element}><Key>${esc(stat.key)}</Key><VersionId>${esc(stat.version)}</VersionId><IsLatest>${latest}</IsLatest><LastModified>${unix_iso(stat.modified)}</LastModified><ETag>&quot;${esc(stat.etag)}&quot;</ETag><Size>${stat.size}</Size><StorageClass>${esc(stat.storage_class)}</StorageClass></${element}>'
	}
	return '<?xml version="1.0" encoding="UTF-8"?>\n<ListVersionsResult xmlns="${xmlns}"><Name>${esc(bucket)}</Name><IsTruncated>false</IsTruncated>${items}</ListVersionsResult>\n'
}

pub fn tagging(tags map[string]string) string {
	mut items := ''
	for key, value in tags {
		items += '<Tag><Key>${esc(key)}</Key><Value>${esc(value)}</Value></Tag>'
	}
	return '<?xml version="1.0" encoding="UTF-8"?>\n<Tagging xmlns="${xmlns}"><TagSet>${items}</TagSet></Tagging>\n'
}

pub fn initiate_upload(bucket string, key string, upload_id string) string {
	return '<?xml version="1.0" encoding="UTF-8"?>\n<InitiateMultipartUploadResult xmlns="${xmlns}"><Bucket>${esc(bucket)}</Bucket><Key>${esc(key)}</Key><UploadId>${esc(upload_id)}</UploadId></InitiateMultipartUploadResult>\n'
}

pub fn list_parts(bucket string, key string, upload_id string, parts []store.Part) string {
	mut items := ''
	for part in parts {
		items += '<Part><PartNumber>${part.number}</PartNumber><ETag>&quot;${esc(part.etag)}&quot;</ETag><Size>${part.size}</Size></Part>'
	}
	return '<?xml version="1.0" encoding="UTF-8"?>\n<ListPartsResult xmlns="${xmlns}"><Bucket>${esc(bucket)}</Bucket><Key>${esc(key)}</Key><UploadId>${esc(upload_id)}</UploadId>${items}</ListPartsResult>\n'
}

pub fn list_uploads(bucket string, uploads []store.Upload) string {
	mut items := ''
	for upload in uploads {
		items += '<Upload><Key>${esc(upload.key)}</Key><UploadId>${esc(upload.upload_id)}</UploadId><Initiated>${unix_iso(upload.initiated)}</Initiated></Upload>'
	}
	return '<?xml version="1.0" encoding="UTF-8"?>\n<ListMultipartUploadsResult xmlns="${xmlns}"><Bucket>${esc(bucket)}</Bucket><IsTruncated>false</IsTruncated>${items}</ListMultipartUploadsResult>\n'
}

pub fn complete_upload(bucket string, key string, etag string) string {
	return '<?xml version="1.0" encoding="UTF-8"?>\n<CompleteMultipartUploadResult xmlns="${xmlns}"><Bucket>${esc(bucket)}</Bucket><Key>${esc(key)}</Key><ETag>&quot;${esc(etag)}&quot;</ETag></CompleteMultipartUploadResult>\n'
}

pub fn versioning_config(state string) string {
	status := if state.len == 0 { '' } else { '<Status>${esc(state)}</Status>' }
	return '<?xml version="1.0" encoding="UTF-8"?>\n<VersioningConfiguration xmlns="${xmlns}">${status}</VersioningConfiguration>\n'
}

// parse_versioning reads the Status element of a versioning configuration.
// Anything other than Enabled or Suspended is rejected.
pub fn parse_versioning(body string) !string {
	state := between(body, '<Status>', '</Status>') or { '' }
	if state != 'Enabled' && state != 'Suspended' && state != '' {
		return error('invalid versioning status')
	}
	return state
}

pub fn lifecycle_config(config lifecycle.Config) string {
	mut rules := ''
	for rule in config.rules {
		filter := if rule.prefix.len > 0 {
			'<Filter><Prefix>${esc(rule.prefix)}</Prefix></Filter>'
		} else {
			'<Filter></Filter>'
		}
		expiration := if rule.expire_days > 0 {
			'<Expiration><Days>${rule.expire_days}</Days></Expiration>'
		} else {
			''
		}
		noncurrent := if rule.noncurrent_days > 0 {
			'<NoncurrentVersionExpiration><NoncurrentDays>${rule.noncurrent_days}</NoncurrentDays></NoncurrentVersionExpiration>'
		} else {
			''
		}
		abort := if rule.abort_days > 0 {
			'<AbortIncompleteMultipartUpload><DaysAfterInitiation>${rule.abort_days}</DaysAfterInitiation></AbortIncompleteMultipartUpload>'
		} else {
			''
		}
		transition := if rule.transition_days > 0 && rule.transition_tier.len > 0 {
			'<Transition><Days>${rule.transition_days}</Days><StorageClass>${esc(rule.transition_tier)}</StorageClass></Transition>'
		} else {
			''
		}
		rules += '<Rule>${filter}${expiration}${noncurrent}${abort}${transition}<Status>Enabled</Status></Rule>'
	}
	return '<?xml version="1.0" encoding="UTF-8"?>\n<LifecycleConfiguration xmlns="${xmlns}">${rules}</LifecycleConfiguration>\n'
}

// parse_lifecycle reads the rules from a LifecycleConfiguration document.
pub fn parse_lifecycle(body string) ![]lifecycle.Rule {
	mut rules := []lifecycle.Rule{}
	mut rest := body
	for {
		rule := between(rest, '<Rule>', '</Rule>') or { break }
		expiration := between(rule, '<Expiration>', '</Expiration>') or { '' }
		transition := between(rule, '<Transition>', '</Transition>') or { '' }
		noncurrent := between(rule, '<NoncurrentVersionExpiration>', '</NoncurrentVersionExpiration>') or { '' }
		noncurrent_transition := between(rule, '<NoncurrentVersionTransition>', '</NoncurrentVersionTransition>') or { '' }
		rules << lifecycle.Rule{
			prefix:                     between(rule, '<Prefix>', '</Prefix>') or { '' }
			expire_days:                (between(expiration, '<Days>', '</Days>') or { '0' }).int()
			noncurrent_days:            (between(noncurrent, '<NoncurrentDays>', '</NoncurrentDays>') or { '0' }).int()
			abort_days:                 (between(rule, '<DaysAfterInitiation>', '</DaysAfterInitiation>') or { '0' }).int()
			tags:                       lifecycle_tags(rule)
			min_size:                   (between(rule, '<ObjectSizeGreaterThan>', '</ObjectSizeGreaterThan>') or { '0' }).i64()
			max_size:                   (between(rule, '<ObjectSizeLessThan>', '</ObjectSizeLessThan>') or { '0' }).i64()
			lock_boundary:              rule.contains('<ObjectLockBoundary>Enabled</ObjectLockBoundary>')
			transition_days:            (between(transition, '<Days>', '</Days>') or { '0' }).int()
			transition_tier:            between(transition, '<StorageClass>', '</StorageClass>') or { '' }
			noncurrent_transition_days: (between(noncurrent_transition, '<NoncurrentDays>', '</NoncurrentDays>') or { '0' }).int()
		}
		rest = rest.all_after('</Rule>')
	}
	return rules
}

fn lifecycle_tags(rule string) map[string]string {
	mut tags := map[string]string{}
	mut rest := rule
	for {
		tag := between(rest, '<Tag>', '</Tag>') or { break }
		name := between(tag, '<Key>', '</Key>') or { '' }
		value := between(tag, '<Value>', '</Value>') or { '' }
		if name.len > 0 {
			tags[name] = value
		}
		rest = rest.all_after('</Tag>')
	}
	return tags
}

pub fn retention_xml(mode string, until i64) string {
	body := if mode.len == 0 {
		''
	} else {
		'<Mode>${esc(mode)}</Mode><RetainUntilDate>${unix_iso(until)}</RetainUntilDate>'
	}
	return '<?xml version="1.0" encoding="UTF-8"?>\n<Retention xmlns="${xmlns}">${body}</Retention>\n'
}

pub fn legal_hold_xml(on bool) string {
	status := if on { 'ON' } else { 'OFF' }
	return '<?xml version="1.0" encoding="UTF-8"?>\n<LegalHold xmlns="${xmlns}"><Status>${status}</Status></LegalHold>\n'
}

// parse_retention reads a Retention document into a mode and a unix timestamp.
pub fn parse_retention(body string) !(string, i64) {
	mode := between(body, '<Mode>', '</Mode>') or { return error('missing retention mode') }
	raw := between(body, '<RetainUntilDate>', '</RetainUntilDate>') or {
		return error('missing retain until date')
	}
	return mode, parse_iso(raw)
}

// parse_legal_hold reads a LegalHold document.
pub fn parse_legal_hold(body string) !bool {
	status := between(body, '<Status>', '</Status>') or { return error('missing legal hold status') }
	if status != 'ON' && status != 'OFF' {
		return error('invalid legal hold status')
	}
	return status == 'ON'
}

fn parse_iso(raw string) i64 {
	parsed := time.parse_iso8601(raw) or { return 0 }
	return parsed.unix()
}

pub fn copy_result(etag string) string {
	return '<?xml version="1.0" encoding="UTF-8"?>\n<CopyObjectResult xmlns="${xmlns}"><ETag>&quot;${esc(etag)}&quot;</ETag></CopyObjectResult>\n'
}

// parse_tagging reads a Tagging document into a map. The grammar is the small
// subset S3 actually sends: one TagSet of Key/Value pairs.
pub fn parse_tagging(body string) !map[string]string {
	mut tags := map[string]string{}
	mut rest := body
	for {
		key := between(rest, '<Key>', '</Key>') or { break }
		value := between(rest, '<Value>', '</Value>') or { break }
		tags[key] = value
		rest = rest.all_after('</Tag>')
	}
	return tags
}

// parse_complete reads the part numbers from a CompleteMultipartUpload
// document, in the order the client listed them.
pub fn parse_complete(body string) ![]int {
	mut numbers := []int{}
	mut rest := body
	for {
		raw := between(rest, '<PartNumber>', '</PartNumber>') or { break }
		numbers << raw.int()
		rest = rest.all_after('</Part>')
	}
	if numbers.len == 0 {
		return error('no parts in completion request')
	}
	return numbers
}

// parse_range reads the first range from a Range header. Only the bytes=start-end
// form is accepted; a suffix range is rejected rather than guessed.
pub fn parse_range(header string) !(i64, i64) {
	spec := header.trim_space().all_after('bytes=').all_before(',')
	ends := spec.split('-')
	if ends.len != 2 || ends[0].len == 0 {
		return error('unsupported range')
	}
	start := i64(ends[0].int())
	end := if ends[1].len == 0 { i64(-1) } else { i64(ends[1].int()) }
	return start, end
}

fn between(body string, open string, close string) ?string {
	start := body.index(open) or { return none }
	after := body[start + open.len..]
	end := after.index(close) or { return none }
	return after[..end]
}

fn esc(s string) string {
	return s.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"',
		'&quot;')
}

fn now_iso() string {
	return unix_iso(time.now().unix())
}

fn unix_iso(unix i64) string {
	return time.unix(unix).custom_format('YYYY-MM-DDTHH:mm:ss')
}
