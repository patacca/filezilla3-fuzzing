#include "filezilla.h"
#include "export.h"
#include "filezillaapp.h"
#include "xmlfunctions.h"
#include "ipcmutex.h"
#include "queue.h"
#include "xrc_helper.h"

#include <wx/filedlg.h>

CExportDialog::CExportDialog(wxWindow* parent, CQueueView* pQueueView)
	: m_parent(parent), m_pQueueView(pQueueView)
{
}

void CExportDialog::Run()
{
}
