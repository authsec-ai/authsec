package integration

import (
	"fmt"
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/internal/azure"
	"github.com/authsec-ai/authsec/services"
)

// Step 7: a storage account block covers its queues, tables and file shares;
// a queue is its own plane (a blob role on the account neither reaches it nor
// blocks it as inherited); Service Bus blocks receive or send, refuses
// delete, and an allow names one of them.
func TestAccessPolicyAzureQueuesAndServiceBus(t *testing.T) {
	z := newAzLab(t)
	z.fake.defs = append(z.fake.defs,
		azureDef(t, z.sub, azure.RoleStorageQueueDataReader, []string{"Microsoft.Storage/storageAccounts/queueServices/queues/read"},
			[]string{"Microsoft.Storage/storageAccounts/queueServices/queues/messages/read"}),
		azureDef(t, z.sub, azure.RoleServiceBusDataReceiver, []string{"Microsoft.ServiceBus/*/queues/read"}, []string{"Microsoft.ServiceBus/*/receive/action"}),
		azureDef(t, z.sub, azure.RoleServiceBusDataSender, []string{"Microsoft.ServiceBus/*/queues/read"}, []string{"Microsoft.ServiceBus/*/send/action"}),
	)

	// The account: a read block takes a queue reader's assignment too.
	qr, qrOID := z.principal("sp-queue-reader")
	z.assign(z.scope, "queue-reader-1", azure.RoleStorageQueueDataReader, qrOID)
	v := z.create("az account read", z.intent("block", z.res, qr, "read"))
	z.run(v.ID)
	if got := z.fake.roles(qrOID); len(got) != 0 {
		t.Fatalf("account block left %v", got)
	}

	// A queue: a blob reader on the account is neither taken nor inherited.
	queue := z.scope + "/queueservices/default/queues/orders"
	queueRes := z.resource("storage_queue", "orders", queue)
	both, bothOID := z.principal("sp-blob-and-queue")
	z.assign(z.scope, "blob-reader-1", azure.RoleStorageBlobDataReader, bothOID)
	z.assign(queue, "queue-reader-2", azure.RoleStorageQueueDataReader, bothOID)
	pv, err := z.svc.Preview(z.ctx, z.ws, z.intent("block", queueRes, both, "read"))
	if err != nil || len(pv.Blockers) != 0 {
		t.Fatalf("queue block: %+v %v", pv, err)
	}
	v = z.create("az queue read", z.intent("block", queueRes, both, "read"))
	z.run(v.ID)
	if got := z.fake.roles(bothOID); len(got) != 1 || got[0] != azure.RoleStorageBlobDataReader {
		t.Fatalf("after the queue block: %v", got)
	}

	// Service Bus.
	ns := "/subscriptions/" + z.sub + "/resourcegroups/rg/providers/microsoft.servicebus/namespaces/sbns"
	z.fake.props[ns] = map[string]any{}
	sbQueue := z.resource("servicebus_queue", "jobs", ns+"/queues/jobs")
	worker, workerOID := z.principal("sp-worker")
	z.assign(ns, "sb-recv-1", azure.RoleServiceBusDataReceiver, workerOID)
	z.assign(ns+"/queues/jobs", "sb-send-1", azure.RoleServiceBusDataSender, workerOID)
	for _, c := range []struct {
		name, effect string
		access       []string
		code         string
	}{
		{"delete", "block", []string{"delete"}, services.GovCodeAccessInvalid},
		{"allow read and write", "allow", []string{"read", "write"}, services.GovCodeAccessInvalid},
		// The receiver role sits on the namespace, above the queue.
		{"block receive inherited from the namespace", "block", []string{"read"}, services.GovCodeAzureInherited},
	} {
		if got := previewCode(z.svc.Preview(z.ctx, z.ws, z.intent(c.effect, sbQueue, worker, c.access...))); got != c.code {
			t.Errorf("%s: %s, want %s", c.name, got, c.code)
		}
	}
	// Block send on the queue: the sender assignment goes, the receiver stays;
	// the namespace takes SAS keys, which is warned.
	pv, err = z.svc.Preview(z.ctx, z.ws, z.intent("block", sbQueue, worker, "write"))
	if err != nil || len(pv.Blockers) != 0 || !strings.Contains(fmt.Sprint(pv.Warnings), services.GovCodeAzureSASKeys) {
		t.Fatalf("block send: %+v %v", pv, err)
	}
	v = z.create("az sb send", z.intent("block", sbQueue, worker, "write"))
	z.run(v.ID)
	if got := z.fake.roles(workerOID); len(got) != 1 || got[0] != azure.RoleServiceBusDataReceiver {
		t.Fatalf("after the send block: %v", got)
	}
	// Allow send: Azure Service Bus Data Sender.
	newcomer, newcomerOID := z.principal("sp-producer")
	a := z.create("az sb allow", z.intent("allow", sbQueue, newcomer, "write"))
	z.run(a.ID)
	if got := z.fake.roles(newcomerOID); len(got) != 1 || got[0] != azure.RoleServiceBusDataSender {
		t.Fatalf("the allow assigned %v", got)
	}
}
