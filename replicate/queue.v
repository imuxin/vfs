// queue is the replication backlog. A failed delivery is remembered so a later
// pass can retry it. The bytes stay in the source bucket; the queue only
// records which object still needs to move.
module replicate

pub struct Job {
pub:
	op           string
	bucket       string
	key          string
	content_type string
}

// enqueue appends a job unless the same object and operation is already waiting.
pub fn enqueue(jobs []Job, job Job) []Job {
	for existing in jobs {
		if existing.op == job.op && existing.bucket == job.bucket && existing.key == job.key {
			return jobs
		}
	}
	mut next := jobs.clone()
	next << job
	return next
}

// without returns the queue after one successful job has been removed.
pub fn without(jobs []Job, done Job) []Job {
	mut next := []Job{}
	mut removed := false
	for job in jobs {
		if !removed && job.op == done.op && job.bucket == done.bucket && job.key == done.key {
			removed = true
			continue
		}
		next << job
	}
	return next
}
