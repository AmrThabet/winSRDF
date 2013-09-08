// PDFParser.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "../../../../SRDF.h"

using namespace Security::Targets::Files;



void view_version(cPDFFile* f);
void view_streams(cPDFFile* f);
void view_xref(cPDFFile* f);
void view_trailer(cPDFFile* f);
void view_objects(cPDFFile* f);
void view_objects_streams(cPDFFile* f);

int _tmain(int argc, _TCHAR* argv[])
{

    //Loading a PDF File
	cPDFFile* pdf = new cPDFFile("Hello.pdf");

	if (!pdf->IsFound())
	{
		cout << "Error: File Not Found\n";
		return 0;
	}

    cout << " ===================== \n\n";
    
    cout << "The pdf file " << endl;
    cout << "   [+]";
    view_version(pdf);		// Printing the PDF Version like "PDF-1.7"
    cout << "   [+]No of objects " << pdf->pdf_objects.size()-1 << " Objects" << endl;
    cout << "   [+]No of streams: " << pdf->stream_no << " Streams" << endl;
    
    cout << "\n\n";
    int choice =6;
    
    do
    {
       
        switch(choice)
        {
            case 0:
                cout << "Exited!" << endl;
                return 0;
            case 1:
                view_objects_streams(pdf);
                break;
            case 2:
                view_streams(pdf);
                break;
            case 3:
                view_xref(pdf);
                break;
            case 4:
                view_trailer(pdf);
                break;
            case 5:
                view_objects(pdf);
                break;
            default:
                break;
        }
        cout << "Enter no 1 to view all objects + streams" << endl;
        cout << "Enter no 2 to view streams only" << endl;
        cout << "Enter no 3 to view xref" << endl;
        cout << "Enter no 4 to view trailer" << endl;
        cout << "Enter no 5 to view objects only" << endl;
        cout << "Enter no 0 to exit" << endl;
        

    } while(cin >> choice);
     
        
    return 0;
}

//Printing the PDF Version
void view_version(cPDFFile* f)
{
    cout << "Version: " << f->FileVersion << endl;
}

//View the PDF Stream (if encoded .. it will print encoded or unreadable data)
//it starts with "stream" and end with "endstream"
void view_streams(cPDFFile* f)
{
	//Loops on all PDF Objects to get their streams
    for(int i=0; i<f->pdf_objects.size();i++)
    {
        if(!f->pdf_objects[i].streams.empty())
        {
            cout <<"Object has the stream no: " << i << endl;
			//get all the streams inside this object
            for(int j=0; j<f->pdf_objects[i].streams.size(); j++)
                cout << f->pdf_objects[i].streams[j] << endl;
        }
    }

}

/*  view the xref data like this
	xref
	0 6
	0000000000 65535 f 
	0000000010 00000 n 
	0000000079 00000 n 
	0000000173 00000 n 
	0000000301 00000 n 
	0000000380 00000 n 
*/

void view_xref(cPDFFile* f)
{
    cout << f->xref_obj.name << endl;
     for(int i=f->xref_obj.start; i<f->xref_obj.end; ++i)
         cout << f->xref_obj.xref_table[i].offset << "   " <<  f->xref_obj.xref_table[i].revision_no << "    " << f->xref_obj.xref_table[i].marker << endl;
}

// view the trailer object
void view_trailer(cPDFFile* f)
{
    for(int i =0; i<f->trailer_table.trailer_data.size(); ++i)
     cout << f->trailer_table.trailer_data[i] << endl;
}

/*  view all objects like this:
	5 0 obj  % page content
	<<
	  /Length 44
	>>
*/
void view_objects(cPDFFile* f)
{
    for(int i=0; i<f->pdf_objects.size();i++)
    {
        cout << "########## Object NO: " << i+1 << " #########" <<endl;
        cout << "Offset: " <<  f->pdf_objects[i].offset << endl;
        cout << "Object Data" << endl;
		//print all data inside the object (between "<<" to ">>")
        for(int j=0; j< f->pdf_objects[i].data.size(); j++)
            cout << f->pdf_objects[i].data[j] << endl;
        cout <<"============= END OF the DATA ============" << endl;
    }
}

//view all objects and streams

void view_objects_streams(cPDFFile* f)
{
    
    for(int i=0; i<f->pdf_objects.size();i++)
    {
        cout << "########## Object NO: " << i+1 << " #########" <<endl;
        cout << "Offset: " <<  f->pdf_objects[i].offset << endl;
        cout << "Object Data" << endl;
        for(int j=0; j< f->pdf_objects[i].data.size(); j++)
            cout << f->pdf_objects[i].data[j] << endl;
        cout <<"============= END OF the DATA ============" << endl;
        if(!f->pdf_objects[i].streams.empty())
        {
            cout << "Object has Stream: True" << endl;
            cout << "Stream Content: " << endl;
            for(int j=0; j<f->pdf_objects[i].streams.size(); j++)
            {
                cout << f->pdf_objects[i].streams[j] << endl;
            }
        }
        else
            cout << "Object doesn't have a stream" << endl;
    }

}


