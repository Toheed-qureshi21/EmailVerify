import { Resend } from "resend";
import { config } from "dotenv";

config();

const resend = new Resend(process.env.RESEND_API_KEY);

export const sendEmail = async({to,subject,html}) => {
    try {
        const {data,error} = await resend.emails.send({
            from:`Your App <onboarding@resend.dev>`,
            to,
            subject,
            html
        });
        if(error) console.log(error);
        console.log("Email sent",data);
        
        
    } catch (error) {
        console.error(error);
    }
}
